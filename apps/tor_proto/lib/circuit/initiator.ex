# SPDX-License-Identifier: ISC

defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Implements a circuit of the Tor protocol.
  """

  @type t :: pid()

  @type hop :: %{
          router: TorProto.Router.t(),
          kf: TorCrypto.OnionStream.t(),
          kb: TorCrypto.OnionStream.t(),
          df: TorCrypto.Digest.t(),
          db: TorCrypto.Digest.t()
        }
  @type hops :: list(hop)

  require Logger
  use GenServer

  ## Generic Functions

  @spec decrypt_relay_cell(binary(), hops()) :: {TorCell.RelayCell.t(), hops()}
  defp decrypt_relay_cell(os, hops) do
    hop = List.last(hops)
    kbs = Enum.map(hops, fn x -> x.kb end)
    {true, cell, db} = TorCell.RelayCell.decrypt(os, kbs, hop.db)

    hop = Map.replace!(hop, :db, db)
    hops = List.replace_at(hops, -1, hop)

    {cell, hops}
  end

  @spec encrypt_relay_cell(TorCell.RelayCell.t(), hops()) :: {binary(), hops()}
  defp encrypt_relay_cell(cell, hops) do
    hop = List.last(hops)
    kfs = Enum.map(hops, fn x -> x.kf end)
    {os, df} = TorCell.RelayCell.encrypt(cell, kfs, hop.df)

    hop = Map.replace!(hop, :df, df)
    hops = List.replace_at(hops, -1, hop)

    {os, hops}
  end

  @spec gen_specs(TorProto.Router.t()) :: list(TorCell.RelayCell.Extend2.Spec.t())
  defp gen_specs(router) do
    specs = [
      %TorCell.RelayCell.Extend2.Spec{
        lstype: :tls_over_tcp4,
        lspec: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp4{ip: router.ip4, port: router.orport}
      },
      %TorCell.RelayCell.Extend2.Spec{
        lstype: :legacy_identity,
        lspec: %TorCell.RelayCell.Extend2.Spec.LegacyIdentity{fingerprint: router.identity}
      },
      %TorCell.RelayCell.Extend2.Spec{
        lstype: :ed25519_identity,
        lspec: %TorCell.RelayCell.Extend2.Spec.Ed25519Identity{
          fingerprint: router.keys.ed25519_identity
        }
      }
    ]

    ip6 = %TorCell.RelayCell.Extend2.Spec{
      lstype: :tls_over_tcp6,
      lspec: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp6{
        ip: router.ip6,
        port: router.orport
      }
    }

    if router.ip6 == nil do
      specs
    else
      specs ++ [ip6]
    end
  end

  @spec gen_stream_id(map()) :: integer()
  defp gen_stream_id(streams) do
    stream_id = Enum.random(1..(2 ** 16 - 1))

    # TODO: Ensure that this does not run forever
    case Map.get(streams, stream_id) do
      nil -> stream_id
      _ -> gen_stream_id(streams)
    end
  end

  @spec ntor(TorCell.circ_id(), TorProto.Connection.Initiator.t(), hops(), TorProto.Router.t()) ::
          hops()
  defp ntor(circ_id, connection, hops, router) do
    b = router.keys.x25519_ntor
    id = router.identity
    {x_pk, x_sk} = TorCrypto.Handshake.Ntor.Client.stage1()

    hdata = TorCrypto.Handshake.Ntor.Client.stage2(b, id, x_pk)

    {cell, hops} =
      if length(hops) == 0 do
        # Use CREATE2
        {%TorCell{
           circ_id: circ_id,
           cmd: :create2,
           payload: %TorCell.Create2{htype: :ntor, hdata: hdata}
         }, []}
      else
        # Use RELAY_EXTEND2
        cell = %TorCell.RelayCell{
          cmd: :extend2,
          stream_id: 0,
          data: %TorCell.RelayCell.Extend2{specs: gen_specs(router), htype: :ntor, hdata: hdata}
        }

        {os, hops} = encrypt_relay_cell(cell, hops)

        {%TorCell{
           circ_id: circ_id,
           cmd: :relay_early,
           payload: %TorCell.RelayEarly{onion_skin: os}
         }, hops}
      end

    sendcell(connection, cell)
    Logger.debug("Sent circuit handshake")

    cell = recvcell(connection)

    {hdata, hops} =
      if length(hops) == 0 do
        %TorCell{circ_id: ^circ_id, cmd: :created2, payload: %TorCell.Created2{hdata: hdata}} =
          cell

        {hdata, []}
      else
        %TorCell{circ_id: ^circ_id, cmd: :relay, payload: %TorCell.Relay{onion_skin: os}} = cell
        {cell, hops} = decrypt_relay_cell(os, hops)

        %TorCell.RelayCell{
          cmd: :extended2,
          stream_id: 0,
          data: %TorCell.RelayCell.Extended2{hdata: hdata}
        } = cell

        {hdata, hops}
      end

    Logger.debug("Received circuit handshake reply")

    remaining = hdata
    <<y::binary-size(32), remaining::binary>> = remaining
    <<auth::binary-size(32), _::binary>> = remaining

    # TODO: Check if Y is in G
    secret_input = TorCrypto.Handshake.Ntor.Client.stage3(b, id, x_pk, x_sk, y)

    true = TorCrypto.Handshake.Ntor.Client.is_valid?(secret_input, auth, b, id, x_pk, y)
    Logger.debug("Circuit handshake is valid")

    keys = TorCrypto.Handshake.Ntor.derive_keys(secret_input)
    Logger.debug("Circuit handshake finished")

    hops ++
      [
        %{
          router: router,
          kf: TorCrypto.OnionStream.init(keys.kf, true),
          kb: TorCrypto.OnionStream.init(keys.kb, false),
          df: TorCrypto.Digest.init(keys.df),
          db: TorCrypto.Digest.init(keys.db)
        }
      ]
  end

  @spec terminate_streams(list(TorProto.Stream.t())) :: :ok
  defp terminate_streams(streams) when length(streams) > 0 do
    TorProto.Stream.Initiator.stop(hd(streams))
    terminate_streams(tl(streams))
  end

  defp terminate_streams(_) do
    :ok
  end

  @spec recvcell(TorProto.Connection.Initiator.t()) :: TorCell.t()
  defp recvcell(connection) do
    case TorProto.Connection.Initiator.dequeue(connection) do
      {:ok, cell} -> cell
      {:error, :empty} -> recvcell(connection)
    end
  end

  @spec sendcell(TorProto.Connection.Initiator.t(), TorCell.t()) :: :ok
  defp sendcell(connection, cell) do
    TorProto.Connection.Initiator.send_cell(connection, cell)
  end

  ## GenServer Callbacks

  @impl true
  def init(init_arg) do
    {:ok, init_arg, {:continue, :create}}
  end

  @impl true
  def handle_continue(:create, state) do
    router = state[:router]
    hops = ntor(state[:circ_id], state[:connection], [], router)

    nicks = [router.nickname]
    Logger.info("Successfully established a circuit with #{router.nickname} => #{inspect(nicks)}")

    state = %{
      # The circuit ID assigned to us by the connection
      circ_id: state[:circ_id],
      # The PID of the connection process we are associated with
      connection: state[:connection],
      # The FIFOS for the stream processes
      fifos: TorProto.PidFifos.init(),
      # The hops that our circuit is made of (contains the crypto keys)
      hops: hops,
      # The stream_id => PID mapping of the stream processes
      streams: %{}
    }

    {:noreply, state}
  end

  @impl true
  def terminate(:normal, state) do
    terminate_streams(Map.values(state[:streams]))
    Logger.debug("Successfully terminated all streams")

    destroy = %TorCell{
      circ_id: state[:circ_id],
      cmd: :destroy,
      payload: %TorCell.Destroy{reason: :finished}
    }

    sendcell(state[:connection], destroy)
    TorProto.Connection.Initiator.destroy(state[:connection], state[:circ_id])

    nicks = Enum.map(state[:hops], fn hop -> hop.router.nickname end)
    Logger.info("Successfully destroyed circuit #{inspect(nicks)}")
    :normal
  end

  @impl true
  def handle_call(:dequeue, from, state) do
    {pid, _} = from

    # If pid does not match the PID in streams, then something fishy is going on
    true = Enum.member?(Map.values(state[:streams]), pid)

    {fifos, cell} = TorProto.PidFifos.dequeue(state[:fifos], pid)

    state = Map.replace!(state, :fifos, fifos)

    case cell do
      nil -> {:reply, {:error, :empty}, state}
      _ -> {:reply, {:ok, cell}, state}
    end
  end

  @impl true
  def handle_call({:connect, host, port}, _from, state) do
    stream_id = gen_stream_id(state[:streams])

    {:ok, stream} = TorProto.Stream.Initiator.start_link(stream_id, self(), host, port)
    streams = Map.put(state[:streams], stream_id, stream)

    state = Map.replace!(state, :streams, streams)
    {:reply, {:ok, stream}, state}
  end

  @impl true
  def handle_call({:extend, router}, _from, state) do
    hops = ntor(state[:circ_id], state[:connection], state[:hops], router)

    nicks = Enum.map(hops, fn hop -> hop.router.nickname end)
    Logger.info("Successfully extended circuit to #{router.nickname} => #{inspect(nicks)}")

    state = Map.replace!(state, :hops, hops)
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:disconnect, stream_id, pid}, state) do
    # If pid does not match the PID in streams, then something fishy is going on
    true = Map.get(state[:streams], stream_id) == pid

    streams = Map.delete(state[:streams], stream_id)
    fifos = TorProto.PidFifos.kill(state[:fifos], pid)

    state = Map.replace!(state, :streams, streams)
    state = Map.replace!(state, :fifos, fifos)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:poll, pid}, state) do
    # Only the connection may poll
    ^pid = state[:connection]

    case TorProto.Connection.Initiator.dequeue(state[:connection]) do
      {:error, :empty} ->
        {:noreply, state}

      {:ok, cell} ->
        circ_id = state[:circ_id]
        %TorCell{circ_id: ^circ_id, cmd: :relay, payload: %TorCell.Relay{onion_skin: os}} = cell
        {cell, hops} = decrypt_relay_cell(os, state[:hops])
        state = Map.replace!(state, :hops, hops)

        if cell.stream_id == 0 do
          raise "TODO"
        else
          # Determine the stream to redirect the cell to
          stream = Map.get(state[:streams], cell.stream_id)
          # If there is no PID with that stream ID, something is fishy
          true = stream != nil

          fifos = TorProto.PidFifos.enqueue(state[:fifos], stream, cell)
          TorProto.Stream.Initiator.poll(stream)

          state = Map.replace!(state, :fifos, fifos)
          {:noreply, state}
        end
    end
  end

  @impl true
  def handle_cast({:send_cell, cell, pid}, state) do
    # If pid does not match the PID in streams, then something fishy is going on
    true = Map.get(state[:streams], cell.stream_id) == pid

    {os, hops} = encrypt_relay_cell(cell, state[:hops])

    cell = %TorCell{
      circ_id: state[:circ_id],
      cmd: :relay,
      payload: %TorCell.Relay{onion_skin: os}
    }

    sendcell(state[:connection], cell)

    state = Map.replace!(state, :hops, hops)
    {:noreply, state}
  end

  ## Client API

  @doc """
  Starts a circuit on an existing connection.

  This function should only be called from the accompanying connection process.
  """
  @spec start_link(TorCell.circ_id(), TorProto.Connection.Initiator.t(), TorProto.Router.t()) ::
          :ok | {:error, term()}
  def start_link(circ_id, connection, router) do
    {:ok, circuit} =
      GenServer.start_link(__MODULE__, %{circ_id: circ_id, connection: connection, router: router})

    {:ok, circuit}
  end

  @doc """
  Terminates a circuit, including all its associated streams.
  """
  @spec stop(t()) :: :ok | {:error, term()}
  def stop(server) do
    GenServer.stop(server, :normal)
  end

  @doc """
  Dequeues a cell from the FIFO.

  This function can only be called from stream processes.
  A violation against this will result in a termination of the process.
  """
  @spec dequeue(t()) :: {:ok, TorCell.t()} | {:error, term()}
  def dequeue(server) do
    GenServer.call(server, :dequeue)
  end

  @doc """
  Creates a new stream on the circuit with a random circuit ID.
  """
  @spec connect(t(), :inet.hostname(), :inet.port_number()) :: :ok | {:error, term()}
  def connect(server, host, port) do
    GenServer.call(server, {:connect, host, port})
  end

  @doc """
  Destroys a stream on the circuit.

  This function can only be called from stream processes.
  A violation against this will result in a termination of the process.
  """
  @spec disconnect(t(), TorCell.RelayCell.stream_id()) :: :ok | {:error, term()}
  def disconnect(server, stream_id) do
    GenServer.cast(server, {:disconnect, stream_id, self()})
  end

  @doc """
  Extends a circuit by another hop.
  """
  @spec extend(t(), TorProto.Router.t()) :: :ok | {:error, term()}
  def extend(server, router) do
    GenServer.call(server, {:extend, router})
  end

  @doc """
  Tells the GenServer that a new cell is available from its connection.

  This function can only be called by the connection process.
  A violation against this will result in a termination of the process.
  """
  @spec poll(t()) :: :ok | {:error, term()}
  def poll(server) do
    GenServer.cast(server, {:poll, self()})
  end

  @doc """
  Sends a cell out of the circuit.

  This function can only be called from stream processes.
  A violation against this will result in a termination of the process.
  """
  @spec send_cell(t(), TorCell.RelayCell.t()) :: :ok | {:error, term()}
  def send_cell(server, cell) do
    GenServer.cast(server, {:send_cell, cell, self()})
  end
end
