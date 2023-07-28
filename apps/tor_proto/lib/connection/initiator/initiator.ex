# SPDX-License-Identifier: ISC

defmodule TorProto.Connection.Initiator do
  @moduledoc """
  Implements a connection of the Tor protocol.
  """

  @type t :: pid()

  require Logger
  use GenServer

  ## Generic Functions

  @spec terminate_circuits(list(TorProto.Circuit.Initiator.t())) :: :ok
  defp terminate_circuits(circuits) when length(circuits) > 0 do
    :ok = TorProto.Circuit.Initiator.stop(hd(circuits))
    terminate_circuits(tl(circuits))
  end

  defp terminate_circuits(_) do
    :ok
  end

  @spec recv_cell(TorProto.Connection.Initiator.Satellite.t()) :: TorCell.t()
  defp recv_cell(satellite) do
    case TorProto.Connection.Initiator.Satellite.dequeue(satellite) do
      {:ok, cell} -> cell
      {:error, :empty} -> recv_cell(satellite)
    end
  end

  @spec sendcell(TorProto.Connection.Initiator.Satellite.t(), TorCell.t()) :: :ok
  defp sendcell(satellite, cell) do
    :ok = TorProto.Connection.Initiator.Satellite.send_cell(satellite, cell)
  end

  @spec valid_cert?(TorCell.Certs.Cert.t(), TorProto.Router.Keys.t()) :: boolean()
  defp valid_cert?(cert, keys) do
    case cert.cert_type do
      :rsa_link -> :public_key.pkix_verify(cert.certificate, keys.rsa_identity)
      :rsa_id -> :public_key.pkix_verify(cert.certificate, keys.rsa_identity)
      :rsa_auth -> :public_key.pkix_verify(cert.certificate, keys.rsa_identity)
      :ed25519_id_signing -> TorCert.Ed25519.is_valid?(cert.certificate, keys.ed25519_identity)
      :ed25519_signing_link -> TorCert.Ed25519.is_valid?(cert.certificate, keys.ed25519_signing)
      :ed25519_signing_auth -> TorCert.Ed25519.is_valid?(cert.certificate, keys.ed25519_signing)
      :rsa_ed25519_cross_cert -> TorCert.RsaEd25519.is_valid?(cert.certificate, keys.rsa_identity)
    end
  end

  @spec valid_certs?(TorCell.Certs.certs(), TorProto.Router.Keys.t()) :: boolean()
  defp valid_certs?(certs, keys) when length(certs) > 0 do
    if valid_cert?(hd(certs), keys) do
      valid_certs?(tl(certs), keys)
    else
      Logger.warning("Invalid certificate: #{inspect(hd(certs))}")
      false
    end
  end

  defp valid_certs?(_, _) do
    true
  end

  ## GenServer Callbacks

  @impl true
  def init(init_arg) do
    router = init_arg[:router]

    ip =
      if router.ip6 == nil do
        router.ip4
      else
        router.ip6
      end

    {:ok, satellite} =
      TorProto.Connection.Initiator.Satellite.start_link(ip, router.orport, self())

    Logger.debug("Created connection satellite process #{inspect(satellite)}")

    :ok =
      sendcell(satellite, %TorCell{
        circ_id: 0,
        cmd: :versions,
        payload: %TorCell.Versions{versions: [4]}
      })

    Logger.debug("Sent VERSIONS cell")
    versions = recv_cell(satellite)

    %TorCell{circ_id: 0, cmd: :versions, payload: %TorCell.Versions{versions: versions}} =
      versions

    Logger.debug("Received VERSIONS cell with #{inspect(versions)}")
    true = Enum.member?(versions, 4)
    Logger.debug("Using link protocol version 4")

    certs = recv_cell(satellite)
    %TorCell{circ_id: 0, cmd: :certs, payload: %TorCell.Certs{certs: certs}} = certs
    Logger.debug("Received CERTS cell")
    true = valid_certs?(certs, router.keys)
    Logger.debug("All certificates are valid")

    auth_challenge = recv_cell(satellite)
    %TorCell{circ_id: 0, cmd: :auth_challenge, payload: _} = auth_challenge
    Logger.debug("Received AUTH_CHALLENGE cell")

    netinfo = recv_cell(satellite)
    %TorCell{circ_id: 0, cmd: :netinfo, payload: netinfo} = netinfo
    Logger.debug("Received NETINFO cell")
    true = Enum.member?(netinfo.myaddrs, ip)
    Logger.debug("NETINFO cell is valid")

    sendcell(satellite, %TorCell{
      circ_id: 0,
      cmd: :netinfo,
      payload: %TorCell.Netinfo{
        time: DateTime.from_unix!(0),
        otheraddr: ip,
        myaddrs: []
      }
    })

    Logger.debug("Sent NETINFO cell")
    Logger.debug("Connection handshake finished")
    Logger.info("Successfully established a connection with #{router.nickname}")

    state = %{
      # The circ_id => PID mapping of the circuit processes
      circuits: %{},
      # The router struct
      router: router,
      # The PID of the satellite process we've spawned above
      satellite: satellite
    }

    {:ok, state}
  end

  @impl true
  def terminate(:normal, state) do
    :ok = terminate_circuits(Map.values(state[:circuits]))
    Logger.debug("Successfully terminated all circuits")

    TorProto.Connection.Initiator.Satellite.stop(state[:satellite])
    Logger.debug("Successfully terminated the connection satellite process")

    router = state[:router]
    Logger.info("Successfully terminated the connection to #{router.nickname}")
    :normal
  end

  @impl true
  def handle_call(:dequeue, from, state) do
    {pid, _} = from

    # If pid does not match the PID in circuits, then something fishy is going on
    true = Map.get(state[:circuits], state[:circ_id]) == pid

    {fifos, cell} = TorProto.PidFifos.dequeue(state[:fifos], pid)

    state = Map.replace!(state, :fifos, fifos)

    if cell == nil do
      {:reply, {:error, :empty}, state}
    else
      {:reply, {:ok, cell}, state}
    end
  end

  @impl true
  def handle_call(:create, _from, state) do
    raise "TODO"
    {:reply, {:ok, nil}, state}
  end

  @impl true
  def handle_call({:destroy, circ_id}, from, state) do
    {pid, _} = from

    # If pid does not match the PID in circuits, then something fishy is going on
    true = Map.get(state[:circuits], circ_id) == pid

    circuits = Map.delete(state[:circuits], circ_id)
    fifos = TorProto.PidFifos.kill(state[:fifos], pid)

    state = Map.replace!(state, :circuits, circuits)
    state = Map.replace!(state, :fifos, fifos)
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:poll, pid}, state) do
    # Only the satellite may poll
    ^pid = state[:satellite]

    {res, cell} = TorProto.Connection.Initiator.Satellite.dequeue(state[:satellite])

    # TODO: Use a case statement here
    if res == :ok do
      if cell.circ_id == 0 do
        raise "TODO"
      else
        # Redirect the cell to the circuit
        circuit = Map.get(state[:circuits], cell.circ_id)
        # If there is no PID with that circuit ID, something is fishy
        true = circuit != nil

        fifos = TorProto.PidFifos.enqueue(state[:fifos], circuit, cell)
        :ok = TorProto.Circuit.Initiator.poll(circuit)

        state = Map.replace!(state, :fifos, fifos)
        {:noreply, state}
      end
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:send_cell, cell, pid}, state) do
    # If pid does not match the PID in circuits, then something fishy is going on
    true = Map.get(state[:circuits], cell.circ_id) == pid

    :ok = sendcell(state[:satellite], cell)

    {:noreply, state}
  end

  ## Client API

  @doc """
  Starts a connection to an onion router.

  This function will spawn a new process and will return, once that process
  has created the TLS connection and performed the in-protocol handshake.
  """
  @spec start_link(TorProto.Router.t()) :: :ok | {:error, term()}
  def start_link(router) do
    {:ok, server} = GenServer.start_link(__MODULE__, %{router: router})
    {:ok, server}
  end

  @doc """
  Terminates a connection, including all its associated circuits and streams.
  """
  @spec stop(t()) :: :ok | {:error, term()}
  def stop(server) do
    GenServer.stop(server)
  end

  @doc """
  Dequeues a cell from the FIFO.

  This function can only be called from circuit processes.
  A violation against this will result in a termination of the process.
  """
  @spec dequeue(t()) :: {:ok, TorCell.t()} | {:error, term()}
  def dequeue(server) do
    GenServer.call(server, :dequeue)
  end

  @doc """
  Creates a new circuit on the connection with a random circuit ID.
  """
  @spec create(t()) :: :ok | {:error, term()}
  def create(server) do
    GenServer.call(server, :create)
  end

  @doc """
  Destroys a circuit.

  This function can only be called from circuit processes.
  A violation against this will result in a termination of the process.
  """
  @spec destroy(t(), TorCell.circ_id()) :: :ok | {:error, term()}
  def destroy(server, circ_id) do
    GenServer.call(server, {:destroy, circ_id})
  end

  @doc """
  Tells the GenServer that a new cell is available from its satellite.

  This function can only be called by the satellite process.
  A violation against this will result in a termination of the process.
  """
  @spec poll(t()) :: :ok | {:error, term()}
  def poll(server) do
    GenServer.cast(server, {:poll, self()})
  end

  @doc """
  Sends a cell out of the connection.

  This function can only be called from circuit processes.
  A violation against this will result in a termination of the process.
  """
  @spec send_cell(t(), TorCell.t()) :: :ok | {:error, term()}
  def send_cell(server, cell) do
    GenServer.cast(server, {:send_cell, cell, self()})
  end
end
