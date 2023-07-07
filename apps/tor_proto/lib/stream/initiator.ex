# SPDX-License-Identifier: ISC

defmodule TorProto.Stream.Initiator do
  @moduledoc """
  Manages an initiator of a TCP stream of a circuit in the Tor protocol.
  """
  use GenServer

  defp chunkify(data, n, chunks \\ []) do
    if byte_size(data) >= n do
      <<chunk::binary-size(n), remainder::binary>> = data
      chunkify(remainder, n, chunks ++ [chunk])
    else
      chunks ++ [data]
    end
  end

  defp send_relay_cell(circuit, cell) do
    :ok = GenServer.call(circuit, {:send_relay_cell, cell})
  end

  defp send_relay_cells(circuit, cells) when length(cells) > 0 do
    send_relay_cell(circuit, hd(cells))
    send_relay_cells(circuit, tl(cells))
  end

  defp send_relay_cells(_, _) do
    :ok
  end

  defp wait_relay_cell(circuit) do
    GenServer.call(circuit, :wait_relay_cell, :infinity)
  end

  @impl true
  def init(args) do
    host = args[:host]
    port = args[:port]
    stream_id = args[:stream_id]
    circuit = args[:circuit]
    receiver = args[:receiver]

    begin = %TorCell.RelayCell{
      cmd: :begin,
      stream_id: stream_id,
      data: %TorCell.RelayCell.Begin{
        host: host,
        port: port,
        flags: %{
          ipv6_okay: true,
          ipv4_not_okay: false,
          ipv6_preferred: true
        }
      }
    }

    send_relay_cell(circuit, begin)

    %TorCell.RelayCell{
      cmd: :connected,
      stream_id: ^stream_id,
      data: %TorCell.RelayCell.Connected{ip: _, ttl: _}
    } = wait_relay_cell(circuit)

    state = %{
      circuit: circuit,
      receiver: receiver,
      stream_id: stream_id
    }

    Logger.info("Initialized stream #{args}")

    {:ok, state}
  end

  @impl true
  def handle_call({:recv_relay_cell, cell}, _from, state) do
    stream_id = state[:stream_id]
    %TorCell.RelayCell{cmd: cmd, stream_id: ^stream_id, data: data} = cell

    case cmd do
      :data -> send(state[:receiver], {:recv_data, data.data})
      :end -> GenServer.stop(self(), :normal)
    end
  end

  @impl true
  def handle_call({:send_data, data}, _from, state) do
    cells =
      Enum.map(chunkify(data, 509), fn x ->
        %TorCell.RelayCell{
          cmd: :data,
          stream_id: state[:stream_id],
          data: %TorCell.RelayCell.Data{data: x}
        }
      end)

    send_relay_cells(state[:circuit], cells)
    Logger.debug("Sent " <> byte_size(data) <> " bytes of data")

    {:reply, :ok, state}
  end

  @impl true
  def terminate(:normal, state) do
    end_cell = %TorCell.RelayCell{
      cmd: :end,
      stream_id: state[:stream_id],
      data: %TorCell.RelayCell.End{reason: :destroy}
    }

    send_relay_cell(state[:circuit], end_cell)

    :ok = GenServer.call(state[:circuit], :end_stream)
    Logger.info("Terminated stream")

    :normal
  end
end
