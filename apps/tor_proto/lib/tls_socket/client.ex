# SPDX-License-Identifier: ISC

defmodule TorProto.TlsSocket.Client do
  @moduledoc """
  Implements a TLS client using GenServer.

  The reason why this is done outside of the connection process,
  which may seem unlogical at first, is because the connection
  process has to receive data while currently receiving other
  data, that is, during the connection handshake.

  The `TorProto.TlsSocket.Client` process lives as a child of an
  accompanying `TorProto.Connection.Initiator` process.
  """
  require Logger
  use GenServer

  defp enqueue_cells(fifos, pid, cells) when length(cells) > 0 do
    enqueue_cells(TorProto.PidFifos.enqueue(fifos, pid, hd(cells)), pid, tl(cells))
  end

  defp enqueue_cells(fifos, _, _) do
    fifos
  end

  @spec fetch_cells(binary(), boolean(), list(TorCell.t())) ::
          {list(TorCell.t()), binary(), boolean()}
  defp fetch_cells(buf, virginity, cells \\ []) do
    try do
      {cell, buf} = TorCell.fetch(buf, get_circ_id_len(virginity))

      # Check if the virginity has been lost
      virginity =
        if virginity && cell.cmd == :versions do
          false
        else
          virginity
        end

      fetch_cells(buf, virginity, cells ++ [cell])
    rescue
      MatchError -> {cells, buf, virginity}
    end
  end

  @spec get_circ_id_len(boolean()) :: 2 | 4
  defp get_circ_id_len(virginity) do
    if virginity do
      2
    else
      4
    end
  end

  @impl true
  def init(init_arg) do
    # OR's hostname
    host = init_arg[:host]
    # OR's port
    port = init_arg[:port]
    # The PID of the TorProto.Connection.Initiator process
    connection = init_arg[:connection]

    {:ok, socket} = :ssl.connect(host, port, [{:active, true}, {:verify, :verify_none}])
    Logger.debug("Created TLS connection with #{inspect(host)}:#{port}")

    state = %{
      # The buffer of remaining data that cannot be parsed yet
      buf: <<>>,
      # The Pid Fifos (although only one PID)
      fifos: TorProto.PidFifos.init(),
      # The PID of the parent process
      connection: connection,
      # The actual TLS socket
      socket: socket,
      # There has not been a VERSIONS cell from the OR
      virginity: true
    }

    {:ok, state}
  end

  @impl true
  def terminate(:normal, state) do
    :ok = :ssl.close(state[:socket])
    Logger.debug("Successfully destroyed TLS connection")
    :normal
  end

  @impl true
  def handle_call({:send, cell}, _from, state) do
    :ok = :ssl.send(state[:socket], TorCell.encode(cell, get_circ_id_len(state[:virginity])))
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:dequeue, _from, state) do
    {fifos, cell} = TorProto.PidFifos.dequeue(state[:fifos], state[:connection])

    state = Map.replace!(state, :fifos, fifos)
    {:reply, {:ok, cell}, state}
  end

  @impl true
  def handle_info(msg, state) do
    socket = state[:socket]
    {:ssl, ^socket, data} = msg

    buf = state[:buf] <> :binary.list_to_bin(data)
    {cells, buf, virginity} = fetch_cells(buf, state[:virginity])
    cells = Enum.filter(cells, fn cell -> cell.cmd not in [:padding, :vpadding] end)

    fifos = enqueue_cells(state[:fifos], state[:connection], cells)
    Enum.map(cells, fn _ -> GenServer.cast(state[:connection], :poll) end)

    state = Map.replace!(state, :buf, buf)
    state = Map.replace!(state, :fifos, fifos)
    state = Map.replace!(state, :virginity, virginity)

    {:noreply, state}
  end
end
