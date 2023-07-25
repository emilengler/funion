# SPDX-License-Identifier: ISC

defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Implements a Tor circuit using GenServer.
  """
  require Logger
  use GenServer

  @type create2 :: (binary() -> TorCell.t())
  @type created2 :: (TorCell.t() -> binary())

  @spec gen_stream_id(map()) :: integer()
  defp gen_stream_id(streams) do
    stream_id = Enum.random(1..(2 ** 16 - 1))

    if Map.get(streams, stream_id) == nil do
      stream_id
    else
      gen_stream_id(streams)
    end
  end

  @spec ntor(create2(), created2(), TorProto.Router.t(), pid()) ::
          {%{
             kf: TorCrypto.OnionStream.t(),
             kb: TorCrypto.OnionStream.t(),
             df: TorCrypto.Digest.t(),
             db: TorCrypto.Digest.t()
           }, TorCrypto.Digest.t(), TorCrypto.Digest.t()}
  defp ntor(create2, created2, router, connection) do
    b = router.keys.x25519_ntor
    id = router.identity
    {x_pk, x_sk} = TorCrypto.Handshake.Ntor.Client.stage1()

    # Create the CREATED2 cell
    # The closure gets the handshake data of the ntor handshake and must
    # return a TorCell alongside the updated forward digest.
    {cell, df} = create2.(TorCrypto.Handshake.Ntor.Client.stage2(b, id, x_pk))
    send_cell(connection, cell)
    Logger.debug("Sent circuit handshake")

    # The closure gets the CREATED2 cell and must returns its handshake
    # data alongside the updated backward digest.
    cell = recv_cell(connection)
    {hdata, db} = created2.(cell)
    Logger.debug("Received circuit handshake reply")

    remaining = hdata
    <<y::binary-size(32), remaining::binary>> = remaining
    <<auth::binary-size(32), _::binary>> = remaining

    # TODO: Check if Y is in G.
    secret_input = TorCrypto.Handshake.Ntor.Client.stage3(b, id, x_pk, x_sk, y)

    true = TorCrypto.Handshake.Ntor.Client.is_valid?(secret_input, auth, b, id, x_pk, y)
    Logger.debug("Circuit handshake is valid")

    keys = TorCrypto.Handshake.Ntor.derive_keys(secret_input)

    {
      %{
        router: router,
        kf: TorCrypto.OnionStream.init(keys.kf, true),
        kb: TorCrypto.OnionStream.init(keys.kb, true),
        df: TorCrypto.Digest.init(keys.df),
        db: TorCrypto.Digest.init(keys.db)
      },
      df,
      db
    }
  end

  @spec terminate_streams(list(pid())) :: :ok
  defp terminate_streams(streams) when length(streams) > 0 do
    GenServer.stop(hd(streams))
    terminate_streams(tl(streams))
  end

  defp terminate_streams(_) do
    :ok
  end

  @spec recv_cell(pid()) :: TorCell.t()
  defp recv_cell(connection) do
    # TODO: Let :dequeue not return :ok if nil
    {:ok, cell} = GenServer.call(connection, :dequeue)

    if cell == nil do
      recv_cell(connection)
    else
      cell
    end
  end

  @spec send_cell(pid(), TorCell.t()) :: :ok
  defp send_cell(connection, cell) do
    GenServer.cast(connection, {:send, cell})
  end

  @impl true
  def init(init_args) do
    circ_id = init_args[:circ_id]
    connection = init_args[:connection]
    router = init_args[:router]

    # The initialization has to take place in an asynchronous fashion,
    # because we need to interact with the connection process during
    # our true initialization.
    GenServer.cast(self(), {:init, circ_id, connection, router})

    {:ok, nil}
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

    send_cell(state[:connection], destroy)
    GenServer.cast(state[:connection], {:end, state[:circ_id]})

    nicks = Enum.map(state[:hops], fn hop -> hop.router.nickname end)
    Logger.info("Successfully destroyed circuit #{inspect(nicks)}")
    :normal
  end

  @impl true
  def handle_call({:connect, host, port}, _from, state) do
    stream_id = gen_stream_id(state[:streams])

    {:ok, stream} =
      GenServer.start_link(TorProto.Stream.Initiator, %{
        circuit: self(),
        host: host,
        port: port,
        stream_id: stream_id
      })

    state = Map.replace!(state, :streams, Map.put(state[:streams], stream_id, stream))
    {:reply, {:ok, stream}, state}
  end

  @impl true
  def handle_call(:dequeue, from, state) do
    {pid, _} = from
    {fifos, cell} = TorProto.PidFifos.dequeue(state[:fifos], pid)

    state = Map.replace!(state, :fifos, fifos)
    {:reply, {:ok, cell}, state}
  end

  @impl true
  def handle_call({:extend, router}, _from, state) do
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

    specs =
      if router.ip6 == nil do
        specs
      else
        specs ++
          [
            %TorCell.RelayCell.Extend2.Spec{
              lstype: :tls_over_tcp6,
              lspec: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp6{
                ip: router.ip6,
                port: router.orport
              }
            }
          ]
      end

    extend2 = fn hdata ->
      extend2 = %TorCell.RelayCell{
        cmd: :extend2,
        stream_id: 0,
        data: %TorCell.RelayCell.Extend2{specs: specs, htype: :ntor, hdata: hdata}
      }

      df = List.last(state[:hops]).df
      kfs = Enum.map(state[:hops], fn x -> x.kf end)
      {os, df} = TorCell.RelayCell.encrypt(extend2, kfs, df)

      {
        %TorCell{
          circ_id: state[:circ_id],
          cmd: :relay_early,
          payload: %TorCell.RelayEarly{onion_skin: os}
        },
        df
      }
    end

    extended2 = fn extended2 ->
      circ_id = state[:circ_id]

      %TorCell{circ_id: ^circ_id, cmd: :relay, payload: %TorCell.Relay{onion_skin: os}} =
        extended2

      db = List.last(state[:hops]).db
      kbs = Enum.map(state[:hops], fn x -> x.kb end)
      {true, extended2, db} = TorCell.RelayCell.decrypt(os, kbs, db)

      %TorCell.RelayCell{
        cmd: :extended2,
        stream_id: 0,
        data: %TorCell.RelayCell.Extended2{hdata: hdata}
      } = extended2

      {hdata, db}
    end

    {next_hop, df, db} = ntor(extend2, extended2, router, state[:connection])

    hop = List.last(state[:hops])
    hop = Map.replace!(hop, :df, df)
    hop = Map.replace!(hop, :db, db)
    state = Map.replace!(state, :hops, List.replace_at(state[:hops], -1, hop))
    state = Map.replace!(state, :hops, state[:hops] ++ [next_hop])

    nicks = Enum.map(state[:hops], fn hop -> hop.router.nickname end)
    Logger.info("Successfully extended circuit to #{router.nickname} => #{inspect(nicks)}")
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:end, stream_id}, state) do
    # TODO: Ensure that PID is correct
    pid = Map.get(state[:streams], stream_id)

    state = Map.replace!(state, :streams, Map.delete(state[:streams], stream_id))
    state = Map.replace!(state, :fifos, TorProto.PidFifos.kill(state[:fifos], pid))
    {:noreply, state}
  end

  @impl true
  def handle_cast({:init, circ_id, connection, router}, state) do
    nil = state

    create2 = fn hdata ->
      {
        %TorCell{
          circ_id: circ_id,
          cmd: :create2,
          payload: %TorCell.Create2{htype: :ntor, hdata: hdata}
        },
        nil
      }
    end

    created2 = fn created2 ->
      %TorCell{circ_id: ^circ_id, cmd: :created2, payload: %TorCell.Created2{hdata: hdata}} =
        created2

      {hdata, nil}
    end

    {hop, nil, nil} = ntor(create2, created2, router, connection)
    Logger.debug("Circuit handshake finished")

    nicks = [router.nickname]
    Logger.info("Successfully established a circuit with #{router.nickname} => #{inspect(nicks)}")

    state = %{
      circ_id: circ_id,
      connection: connection,
      fifos: TorProto.PidFifos.init(),
      hops: [hop],
      streams: %{}
    }

    {:noreply, state}
  end

  @impl true
  def handle_cast(:poll, state) do
    {:ok, cell} = GenServer.call(state[:connection], :dequeue)

    if cell == nil do
      {:noreply, state}
    else
      circ_id = state[:circ_id]
      ^circ_id = cell.circ_id

      hop = List.last(state[:hops])
      kbs = Enum.map(state[:hops], fn x -> x.kb end)
      {true, cell, db} = TorCell.RelayCell.decrypt(cell.payload.onion_skin, kbs, hop.db)
      hop = Map.replace!(hop, :db, db)

      pid = Map.get(state[:streams], cell.stream_id)
      true = pid != nil

      fifos = TorProto.PidFifos.enqueue(state[:fifos], pid, cell)
      GenServer.cast(pid, :poll)

      state = Map.replace!(state, :hops, List.replace_at(state[:hops], -1, hop))
      state = Map.replace!(state, :fifos, fifos)
      {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:send, cell}, state) do
    # TODO: Ensure that streams cannot send on other stream's behalfs

    hop = List.last(state[:hops])
    kfs = Enum.map(state[:hops], fn x -> x.kf end)
    {os, df} = TorCell.RelayCell.encrypt(cell, kfs, hop.df)

    cell = %TorCell{
      circ_id: state[:circ_id],
      cmd: :relay,
      payload: %TorCell.Relay{onion_skin: os}
    }

    send_cell(state[:connection], cell)

    hop = Map.replace!(hop, :df, df)
    state = Map.replace!(state, :hops, List.replace_at(state[:hops], -1, hop))
    {:noreply, state}
  end
end
