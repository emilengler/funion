# SPDX-License-Identifier: ISC

defmodule TorProto.Stream.Initiator do
  @moduledoc """
  Manages an initiator of a TCP stream of a circuit in the Tor protocol.
  """

  defp chunkify(data, n, chunks \\ []) do
    if byte_size(data) >= n do
      <<chunk::binary-size(n), remainder::binary>> = data
      chunkify(remainder, n, chunks ++ [chunk])
    else
      chunks ++ [data]
    end
  end

  defp recv_relay_cell() do
    receive do
      {:recv_relay_cell, cell} -> cell
    end
  end

  defp send_relay_cell(cell, parent) do
    send(parent, {:send_relay_cell, cell, self()})

    receive do
      {:send_relay_cell, :ok} -> :ok
    end
  end

  defp send_relay_cells(cells, parent) when length(cells) > 0 do
    :ok = send_relay_cell(hd(cells), parent)
    send_relay_cells(tl(cells), parent)
  end

  defp send_relay_cells(_, _) do
    :ok
  end

  defp handler(stream_id, parent, receiver) do
    receive do
      {:end, pid} ->
        end_cell = %TorCell.RelayCell{
          cmd: :end,
          stream_id: stream_id,
          data: %TorCell.RelayCell.End{reason: :done}
        }

        :ok = send_relay_cell(end_cell, parent)

        send(parent, {:end_stream, stream_id, self()})

        receive do
          {:end_stream, :ok} -> nil
        end

        send(pid, {:end, :ok})

      {:recv_relay_cell, relay_cell} ->
        %TorCell.RelayCell{cmd: cmd, stream_id: ^stream_id, data: data} = relay_cell

        case cmd do
          :data -> send(receiver, {:recv_data, data.data})
          :end -> send(self(), {:end, self()})
        end

        handler(stream_id, parent, receiver)

      {:send_data, data, pid} ->
        cells =
          Enum.map(chunkify(data, 509), fn x ->
            %TorCell.RelayCell{
              cmd: :data,
              stream_id: stream_id,
              data: %TorCell.RelayCell.Data{data: x}
            }
          end)

        :ok = send_relay_cells(cells, parent)
        send(pid, {:send_data, :ok})
        handler(stream_id, parent, receiver)
    end
  end

  @doc """
  Creates a fresh stream on an established circuit.

  **DO NOT** use this function on your own!
  Always create streams through circuits.
  """
  def init(host, port, stream_id, parent, receiver) do
    begin = %TorCell.RelayCell{
      cmd: :begin,
      stream_id: stream_id,
      data: %TorCell.RelayCell.Begin{
        host: host,
        port: port
      }
    }

    :ok = send_relay_cell(begin, parent)

    %TorCell.RelayCell{
      cmd: :connected,
      stream_id: ^stream_id,
      data: %TorCell.RelayCell.Connected{ip: _, ttl: _}
    } = recv_relay_cell()

    handler(stream_id, parent, receiver)
  end
end
