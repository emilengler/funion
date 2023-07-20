# SPDX-License-Identifier: ISC

defmodule TorProto.TlsSocket.Client do
  @moduledoc """
  Manages a TLS client.

  The reason why this is done outside of the connection process,
  which may seem unlogical at first, is because the connection
  process has to receive data while currently receiving other
  data, that is, during the connection handshake.

  Due to our usage of active TLS sockets, we cannot combine this
  alongside GenServer, unfortunately.

  This TLS client operates on cell level.  Keep in mind that the
  `circ_id_len` needs to be set to `4` if using a link protocol
  version of 4 or newer.

  The `TorProto.TlsSocket.Client` process lives as a child of an
  accompanying `TorProto.Connection.Initiator` process.
  """
  require Logger
  use GenServer

  @type init_arg() :: %{host: :ssl.host(), port: integer(), connection: pid()}

  @spec fetch_cells(binary(), integer(), list(TorCell.t())) :: {list(TorCell.t()), binary()}
  defp fetch_cells(buf, circ_id_len, cells \\ []) do
    try do
      {cell, buf} = TorCell.fetch(buf, circ_id_len)
      fetch_cells(buf, circ_id_len, cells ++ [cell])
    rescue
      MatchError -> {cells, buf}
    end
  end

  @spec push_to_pool(TorProto.CellPool.t(), pid(), list(TorCell.t()), list(integer())) ::
          {TorProto.CellPool.t(), list(integer())}
  defp push_to_pool(pool, pid, cells, ids) when length(cells) > 0 do
    {pool, id} = TorProto.CellPool.push(pool, pid, hd(cells))
    push_to_pool(pool, pid, tl(cells), ids ++ [id])
  end

  defp push_to_pool(pool, _, _, ids) do
    {pool, ids}
  end

  @impl true
  def init(init_arg) do
    host = init_arg[:host]
    port = init_arg[:port]
    connection = init_arg[:connection]

    {:ok, socket} = :ssl.connect(host, port, active: true)
    Logger.debug("Created TLS connection to #{host}:#{port}")

    state = %{
      buf: nil,
      circ_id_len: 2,
      connection: connection,
      pool: TorProto.CellPool.init(),
      socket: socket
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:send_cell, cell}, from, state) do
    ^from = state[:connection]

    :ok = :ssl.send(state[:socket], TorCell.encode(cell, state[:circ_id_len]))

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:set_circ_id_len, circ_id_len}, from, state) do
    ^from = state[:connection]
    state = Map.replace!(state, :circ_id_len, circ_id_len)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:take, id}, from, state) do
    ^from = state[:connection]
    {pool, cell} = TorProto.CellPool.take(state[:pool], from, id)

    state = Map.replace!(state, :pool, pool)
    {:reply, cell, state}
  end

  @impl true
  def handle_info(msg, state) do
    socket = state[:socket]

    state =
      case msg do
        {:ssl, ^socket, data} ->
          state = Map.replace!(state, :buf, state[:buf] <> :binary.list_to_bin(data))
          {cells, buf} = fetch_cells(state[:buf], state[:circ_id_len])

          {pool, ids} = push_to_pool(state[:pool], state[:connection], cells, [])
          Enum.map(ids, fn id -> GenServer.cast(state[:connection], {:poll, id}) end)

          state = Map.replace!(state, :buf, buf)
          state = Map.replace!(state, :pool, pool)

          state
      end

    {:noreply, state}
  end
end
