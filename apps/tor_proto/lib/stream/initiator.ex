# SPDX-License-Identifier: ISC

defmodule TorProto.Stream.Initiator do
  @moduledoc """
  Implements a Tor stream using GenServer.
  """
  require Logger
  use GenServer

  @spec chunkify(binary(), integer(), list(binary())) :: list(binary())
  defp chunkify(data, n, chunks \\ []) do
    if byte_size(data) >= n do
      <<chunk::binary-size(n), remainder::binary>> = data
      chunkify(remainder, n, chunks ++ [chunk])
    else
      chunks ++ [data]
    end
  end

  @spec recv_cell(pid()) :: TorCell.RelayCell.t()
  defp recv_cell(circuit) do
    # TODO: Let :dequeue not return :ok if nil
    {:ok, cell} = GenServer.call(circuit, :dequeue)

    if cell == nil do
      recv_cell(circuit)
    else
      cell
    end
  end

  @spec send_cell(pid(), TorCell.RelayCell.t()) :: :ok
  defp send_cell(circuit, cell) do
    GenServer.cast(circuit, {:send, cell})
  end

  @impl true
  def init(init_arg) do
    circuit = init_arg[:circuit]
    host = init_arg[:host]
    port = init_arg[:port]
    receiver = init_arg[:receiver]
    stream_id = init_arg[:stream_id]

    # The initialization has to take place in an asynchronous fashion,
    # because we need to interact with the circuit process during
    # our own initialization.
    GenServer.cast(self(), {:init, circuit, host, port, receiver, stream_id})

    {:ok, nil}
  end

  @impl true
  def terminate(:normal, state) do
    end_cell = %TorCell.RelayCell{
      cmd: :end,
      stream_id: state[:stream_id],
      data: %TorCell.RelayCell.End{reason: :done}
    }

    send_cell(state[:circuit], end_cell)
    GenServer.cast(state[:circuit], {:end, state[:stream_id]})

    host = state[:host]
    port = state[:port]
    Logger.info("Successfully destroyed stream to #{inspect(host)}:#{port}")
    :normal
  end

  @impl true
  def handle_cast({:send, data}, state) do
    cells =
      Enum.map(chunkify(data, 509), fn chunk ->
        %TorCell.RelayCell{
          cmd: :data,
          stream_id: state[:stream_id],
          data: %TorCell.RelayCell.Data{data: chunk}
        }
      end)

    Enum.map(cells, fn cell -> send_cell(state[:circuit], cell) end)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:init, circuit, host, port, receiver, stream_id}, state) do
    nil = state

    begin = %TorCell.RelayCell{
      cmd: :begin,
      stream_id: stream_id,
      data: %TorCell.RelayCell.Begin{
        host: host,
        port: port
      }
    }

    send_cell(circuit, begin)
    Logger.debug("Sent RELAY_BEGIN cell")

    cell = recv_cell(circuit)

    # TODO: Implement support for RELAY_END at this stage
    %TorCell.RelayCell{
      cmd: :connected,
      stream_id: ^stream_id,
      data: %TorCell.RelayCell.Connected{ip: ip, ttl: _}
    } = cell

    Logger.debug("Received RELAY_CONNECTED cell")

    Logger.info("Successfully created stream to #{inspect(host)}:#{port} (#{inspect(ip)})")

    state = %{
      circuit: circuit,
      host: host,
      port: port,
      stream_id: stream_id,
      receiver: receiver
    }

    {:noreply, state}
  end

  @impl true
  def handle_cast(:poll, state) do
    {:ok, cell} = GenServer.call(state[:circuit], :dequeue)

    if cell == nil do
      {:noreply, state}
    else
      stream_id = state[:stream_id]
      ^stream_id = cell.stream_id

      # The end has to be treated specially
      case cell.cmd do
        :data -> state[:receiver].(cell.data.data)
        :end -> nil
      end

      if cell.cmd == :end do
        {:stop, :normal, state}
      else
        {:noreply, state}
      end
    end
  end
end
