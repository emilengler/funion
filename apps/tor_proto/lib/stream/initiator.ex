# SPDX-License-Identifier: ISC

defmodule TorProto.Stream.Initiator do
  @moduledoc """
  Implements a stream of the Tor protocol.
  """

  @type t :: pid()

  @type receiver :: (binary() -> :ok)

  require Logger
  use GenServer

  ## Generic Functions

  @spec chunkify(binary(), integer(), list(binary())) :: list(binary())
  defp chunkify(data, n, chunks \\ []) do
    if byte_size(data) >= n do
      <<chunk::binary-size(n), remainder::binary>> = data
      chunkify(remainder, n, chunks ++ [chunk])
    else
      chunks ++ [data]
    end
  end

  @spec recvcell(TorProto.Circuit.Initiator.t()) :: TorCell.RelayCell.t()
  defp recvcell(circuit) do
    case TorProto.Circuit.Initiator.dequeue(circuit) do
      {:ok, cell} -> cell
      {:error, :empty} -> recvcell(circuit)
    end
  end

  @spec sendcell(TorProto.Circuit.Initiator.t(), TorCell.RelayCell.t()) :: :ok
  defp sendcell(circuit, cell) do
    TorProto.Circuit.Initiator.send_cell(circuit, cell)
  end

  @spec sendcells(TorProto.Circuit.Initiator.t(), list(TorCell.RelayCell.t())) :: :ok
  defp sendcells(circuit, cells) when length(cells) > 0 do
    sendcell(circuit, hd(cells))
    sendcells(circuit, tl(cells))
  end

  defp sendcells(_, _) do
    :ok
  end

  ## GenServer Callbacks

  @impl true
  def init(init_arg) do
    {:ok, init_arg, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    host = state[:host]
    port = state[:port]

    sendcell(state[:circuit], %TorCell.RelayCell{
      cmd: :begin,
      stream_id: state[:stream_id],
      data: %TorCell.RelayCell.Begin{host: host, port: port}
    })

    Logger.debug("Sent RELAY_BEGIN cell")

    cell = recvcell(state[:circuit])

    state = %{
      # The PID of the circuit we are associated to
      circuit: state[:circuit],
      # The hostname of the stream
      host: host,
      # The port of the stream
      port: port,
      # The closure that receives all incoming data from the stream
      receiver: state[:receiver],
      # The stream ID that was assigned to us by our circuit
      stream_id: state[:stream_id]
    }

    case cell.cmd do
      :connected ->
        Logger.debug("Received RELAY_CONNECTED cell")

        %TorCell.RelayCell.Connected{ip: ip, ttl: _} = cell.data
        Logger.info("Successfully connected to #{inspect(host)}:#{port} (#{inspect(ip)})")

        {:noreply, state}

      :end ->
        Logger.debug("Received RELAY_END cell: #{inspect(cell.data)}")
        Logger.error("Could not create stream to #{inspect(host)}:#{port}")
        {:stop, :normal, state}
    end
  end

  @impl true
  def terminate(:normal, state) do
    sendcell(state[:circuit], %TorCell.RelayCell{
      cmd: :end,
      stream_id: state[:stream_id],
      data: %TorCell.RelayCell.End{reason: :done}
    })

    TorProto.Circuit.Initiator.disconnect(state[:circuit], state[:stream_id])

    host = state[:host]
    port = state[:port]
    Logger.info("Successfully destroyed stream to #{inspect(host)}:#{port}")
    :normal
  end

  @impl true
  def handle_cast({:poll, pid}, state) do
    # Only the circuit may poll
    ^pid = state[:circuit]

    case TorProto.Circuit.Initiator.dequeue(state[:circuit]) do
      {:error, :empty} ->
        {:noreply, state}

      {:ok, cell} ->
        stream_id = state[:stream_id]
        %TorCell.RelayCell{cmd: cmd, stream_id: ^stream_id, data: data} = cell

        case cmd do
          :data ->
            state[:receiver].(data.data)
            {:noreply, state}

          :end ->
            {:stop, :normal, state}
        end
    end
  end

  @impl true
  def handle_cast({:send_data, data}, state) do
    cells =
      Enum.map(chunkify(data, 509), fn chunk ->
        %TorCell.RelayCell{
          cmd: :data,
          stream_id: state[:stream_id],
          data: %TorCell.RelayCell.Data{data: chunk}
        }
      end)

    sendcells(state[:circuit], cells)

    {:noreply, state}
  end

  ## Client API

  @doc """
  Starts a stream on an existing connection.

  This function should only be called from the accompanying circuit process.
  """
  @spec start_link(
          TorCell.RelayCell.stream_id(),
          TorProto.Circuit.Initiator.t(),
          :inet.hostname(),
          :inet.port_number(),
          receiver()
        ) ::
          {:ok, t()} | {:error, term()}
  def start_link(stream_id, circuit, host, port, receiver) do
    {:ok, stream} =
      GenServer.start_link(__MODULE__, %{
        circuit: circuit,
        host: host,
        port: port,
        receiver: receiver,
        stream_id: stream_id
      })

    {:ok, stream}
  end

  @doc """
  Terminates a stream.
  """
  @spec stop(t()) :: :ok | {:error, term()}
  def stop(server) do
    :ok = GenServer.stop(server, :normal)
  end

  @doc """
  Tells the GenServer that a new cell is available from its circuit.

  This function can only be called by the circuit process.
  A violation against this will result in a termination of the process.
  """
  @spec poll(t()) :: :ok | {:error, term()}
  def poll(server) do
    GenServer.cast(server, {:poll, self()})
  end

  @doc """
  Sends data out of the stream.
  """
  @spec send_data(t(), binary()) :: :ok | {:error, term()}
  def send_data(server, data) do
    GenServer.cast(server, {:send_data, data})
  end
end
