# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Connected do
  @enforce_keys [:ip, :ttl]
  defstruct ip: nil,
            ttl: nil

  @type t :: %TorCell.RelayCell.Connected{ip: tuple(), ttl: integer()}

  @spec decode_v4(binary()) :: TorCell.RelayCell.Connected
  defp decode_v4(data) do
    <<ip::binary-size(4), ttl::32>> = data
    ip = List.to_tuple(:binary.bin_to_list(ip))
    %TorCell.RelayCell.Connected{ip: ip, ttl: ttl}
  end

  @spec decode_v6(binary()) :: TorCell.RelayCell.Connected
  defp decode_v6(data) do
    <<0::32, 6, ip::binary-size(16), ttl::32>> = data
    ip = List.to_tuple(:binary.bin_to_list(ip))
    %TorCell.RelayCell.Connected{ip: ip, ttl: ttl}
  end

  @spec decode(binary()) :: TorCell.RelayCell.Connected
  def decode(data) do
    # Determine the address based on the length
    case byte_size(data) do
      8 -> decode_v4(data)
      25 -> decode_v6(data)
    end
  end

  @spec encode(TorCell.RelayCell.Connected) :: binary()
  def encode(cell) do
    case tuple_size(cell.ip) do
      4 -> :binary.list_to_bin(Tuple.to_list(cell.ip)) <> <<cell.ttl::32>>
      16 -> <<0::32, 6>> <> :binary.list_to_bin(Tuple.to_list(cell.ip)) <> <<cell.ttl::32>>
    end
  end
end
