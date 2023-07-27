# SPDX-License-Identifier: ISC

defmodule TorProto.Connection.Initiator.Satellite do
  @moduledoc """
  Implements the satellite process responsible for handling the TLS traffic
  of an accompanying connection process.
  """

  @type t :: pid()

  require Logger
  use GenServer

  ## Generic Functions

  @spec enqueue_cells(TorProto.PidFifos.t(), pid(), list(TorCell.t())) :: TorProto.PidFifos.t()
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

  @spec poll_connection(TorProto.Connection.t(), integer()) :: :ok
  defp poll_connection(connection, len) when len > 0 do
    :ok = TorProto.Connection.Initiator.poll(connection)
  end

  defp poll_connection(_, 0) do
    :ok
  end

  ## GenServer Callbacks

  @impl true
  def init(init_arg) do
    # OR's hostname
    host = init_arg[:host]
    # OR's port
    port = init_arg[:port]
    # The PID of the connection
    connection = init_arg[:connection]

    {:ok, socket} = :ssl.connect(host, port, [{:active, true}, {:verify, :verify_none}])
    Logger.debug("Created TLS connection with #{inspect(host)}:#{port}")

    state = %{
      # The buffer of remaining data that cannot be parsed yet
      buf: <<>>,
      # The FIFO for the cells of the connection process
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
    Logger.debug("Successfully closed the TLS connection")
    :normal
  end

  @impl true
  def handle_call(:dequeue, from, state) do
    {pid, _} = from
    ^pid = state[:connection]

    {fifos, cell} = TorProto.PidFifos.dequeue(state[:fifos], pid)

    state = Map.replace!(state, :fifos, fifos)

    if cell == nil do
      {:reply, {:error, :empty}, state}
    else
      {:reply, {:ok, cell}, state}
    end
  end

  @impl true
  def handle_call({:send_cell, cell}, from, state) do
    {pid, _} = from
    ^pid = state[:connection]

    :ok = :ssl.send(state[:socket], TorCell.encode(cell, get_circ_id_len(state[:virginity])))

    {:reply, :ok, state}
  end

  @impl true
  def handle_info(msg, state) do
    socket = state[:socket]
    {:ssl, ^socket, data} = msg

    buf = state[:buf] <> :binary.list_to_bin(data)
    {cells, buf, virginity} = fetch_cells(buf, state[:virginity])

    fifos = enqueue_cells(state[:fifos], state[:connection], cells)
    :ok = poll_connection(state[:connection], length(cells))

    state = Map.replace!(state, :buf, buf)
    state = Map.replace!(state, :fifos, fifos)
    state = Map.replace!(state, :virginity, virginity)
    {:noreply, state}
  end

  ## Client API

  @doc """
  Starts the satellite process of a connection initiator.

  It's initialization arguments are as follows:

  * host: The hostname of the OR
  * port: The port of the OR
  * connection: The PID of the connection initiator process.
  """
  @spec start_link(:ssl.host(), :inet.port_number(), pid()) :: {:ok, t()} | {:error, term()}
  def start_link(host, port, connection) do
    {:ok, server} =
      GenServer.start_link(__MODULE__, %{host: host, port: port, connection: connection})

    {:ok, server}
  end

  @doc """
  Terminates the satellite process of a connection initiator,
  by closing the TLS connection.
  """
  @spec stop(t()) :: :ok | {:error, term()}
  def stop(server) do
    GenServer.stop(server)
  end

  @doc """
  Dequeues a cell from the FIFO.

  This function is reserved for the connection process.
  A violation will result in an immediate shutdown.
  """
  @spec dequeue(t()) :: {:ok, TorCell.t()} | {:error, term()}
  def dequeue(server) do
    GenServer.call(server, :dequeue)
  end

  @doc """
  Sends a cell out of the connection.

  This function is reserved for the connection process.
  A violation will result in an immediate shutdown.
  """
  @spec send_cell(t(), TorCell.t()) :: :ok | {:error, term()}
  def send_cell(server, cell) do
    GenServer.call(server, {:send_cell, cell})
  end
end
