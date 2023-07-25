# SPDX-License-Identifer: ISC

defmodule TorProto.Connection.Initiator do
  @moduledoc """
  Implements the initiator of a Tor protocol connection.
  """
  require Logger
  use GenServer

  @spec gen_circ_id(map()) :: integer()
  defp gen_circ_id(circuits) do
    # Set the MSB to 1
    circ_id = Bitwise.bor(2 ** 31, Enum.random(1..(2 ** 32 - 1)))

    # Check if the circ_id already exists
    if Map.get(circuits, circ_id) == nil do
      circ_id
    else
      gen_circ_id(circuits)
    end
  end

  @spec terminate_circuits(list(pid())) :: :ok
  defp terminate_circuits(circuits) when length(circuits) > 0 do
    GenServer.stop(hd(circuits))
    terminate_circuits(tl(circuits))
  end

  defp terminate_circuits(_) do
    :ok
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
      Logger.warn("Invalid certificate: #{inspect(hd(certs))}")
      false
    end
  end

  defp valid_certs?(_, _) do
    true
  end

  @spec recv_cell(pid()) :: TorCell.t()
  defp recv_cell(tls_socket) do
    # TODO: Let :dequeue not return :ok if nil
    {:ok, cell} = GenServer.call(tls_socket, :dequeue)

    if cell == nil do
      recv_cell(tls_socket)
    else
      cell
    end
  end

  @spec send_cell(pid(), TorCell.t()) :: :ok
  defp send_cell(tls_socket, cell) do
    GenServer.cast(tls_socket, {:send, cell})
  end

  @impl true
  def init(init_args) do
    router = init_args[:router]

    ip =
      if router.ip6 != nil do
        router.ip6
      else
        router.ip4
      end

    {:ok, tls_socket} =
      GenServer.start_link(TorProto.TlsSocket.Client, %{
        host: ip,
        port: router.orport,
        connection: self()
      })

    Logger.debug("Created TLS client process with #{inspect(tls_socket)}")

    send_cell(tls_socket, %TorCell{
      circ_id: 0,
      cmd: :versions,
      payload: %TorCell.Versions{versions: [4]}
    })

    Logger.debug("Sent VERSIONS cell")

    versions = recv_cell(tls_socket)

    %TorCell{circ_id: 0, cmd: :versions, payload: %TorCell.Versions{versions: versions}} =
      versions

    Logger.debug("Received VERSIONS cell with #{inspect(versions)}")
    true = Enum.member?(versions, 4)
    Logger.debug("Using link protocol version 4")

    certs = recv_cell(tls_socket)
    %TorCell{circ_id: 0, cmd: :certs, payload: %TorCell.Certs{certs: certs}} = certs
    Logger.debug("Received CERTS cell")
    true = valid_certs?(certs, router.keys)
    Logger.debug("All certificates are valid")

    auth_challenge = recv_cell(tls_socket)
    %TorCell{circ_id: 0, cmd: :auth_challenge, payload: _} = auth_challenge
    Logger.debug("Received AUTH_CHALLENGE cell")

    netinfo = recv_cell(tls_socket)
    %TorCell{circ_id: 0, cmd: :netinfo, payload: netinfo} = netinfo
    Logger.debug("Received NETINFO cell")
    true = Enum.member?(netinfo.myaddrs, ip)
    Logger.debug("NETINFO cell is valid")

    send_cell(tls_socket, %TorCell{
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
      circuits: %{},
      fifos: TorProto.PidFifos.init(),
      router: router,
      tls_socket: tls_socket
    }

    {:ok, state}
  end

  @impl true
  def terminate(:normal, state) do
    terminate_circuits(Map.values(state[:circuits]))
    Logger.debug("Successfully terminated all circuits")

    GenServer.stop(state[:tls_socket])
    Logger.debug("Successfully terminated the TLS client process")

    router = state[:router]
    Logger.info("Successfully terminated the connection to #{router.nickname}")
    :normal
  end

  @impl true
  def handle_call(:create, _from, state) do
    circ_id = gen_circ_id(state[:circuits])

    {:ok, circuit} =
      GenServer.start_link(TorProto.Circuit.Initiator, %{
        circ_id: circ_id,
        connection: self(),
        router: state[:router]
      })

    state = Map.replace!(state, :circuits, Map.put(state[:circuits], circ_id, circuit))
    {:reply, {:ok, circuit}, state}
  end

  @impl true
  def handle_call(:dequeue, from, state) do
    {pid, _} = from
    {fifos, cell} = TorProto.PidFifos.dequeue(state[:fifos], pid)

    state = Map.replace!(state, :fifos, fifos)
    {:reply, {:ok, cell}, state}
  end

  @impl true
  def handle_cast({:end, circ_id}, state) do
    # TODO: Ensure that PID is correct
    pid = Map.get(state[:circuits], circ_id)

    state = Map.replace!(state, :circuits, Map.delete(state[:circuits], circ_id))
    state = Map.replace!(state, :fifos, TorProto.PidFifos.kill(state[:fifos], pid))
    {:noreply, state}
  end

  @impl true
  def handle_cast(:poll, state) do
    {:ok, cell} = GenServer.call(state[:tls_socket], :dequeue)

    if cell == nil do
      {:noreply, state}
    else
      if cell.circ_id == 0 do
        {:noreply, state}
      else
        pid = Map.get(state[:circuits], cell.circ_id)

        if pid == nil do
          Logger.warn("Received cell with unknown circuit ID, ignoring")
          {:noreply, state}
        else
          # Redirect the poll to the circuit
          GenServer.cast(pid, :poll)

          fifos = TorProto.PidFifos.enqueue(state[:fifos], pid, cell)
          state = Map.replace!(state, :fifos, fifos)
          {:noreply, state}
        end
      end
    end
  end

  @impl true
  def handle_cast({:send, cell}, state) do
    # TODO: Ensure that circuit's cannot send on other circuit's behalfs
    send_cell(state[:tls_socket], cell)
    {:noreply, state}
  end
end
