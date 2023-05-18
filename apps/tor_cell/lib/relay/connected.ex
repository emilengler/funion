defmodule TorCell.Relay.Connected do
  defstruct ip: nil,
            ttl: nil

  defp decode_v4(data) do
    <<ip::binary-size(4), ttl::32>> = data

    %TorCell.Relay.Connected{
      ip: List.to_tuple(:binary.bin_to_list(ip)),
      ttl: ttl
    }
  end

  defp decode_v6(data) do
    <<0::32, 6, ip::binary-size(16), ttl::32>> = data

    %TorCell.Relay.Connected{
      ip: List.to_tuple(:binary.bin_to_list(ip)),
      ttl: ttl
    }
  end

  defp encode_v4(cell) do
    :binary.list_to_bin(Tuple.to_list(cell.ip)) <> <<cell.ttl::32>>
  end

  defp encode_v6(cell) do
    <<0::32>> <> <<6>> <> :binary.list_to_bin(Tuple.to_list(cell.ip)) <> <<cell.ttl::32>>
  end

  @doc """
  Decodes the data of a RELAY_CONNECTED TorCell into its internal representation.

  Returns a TorCell.Relay.Connected.
  """
  def decode(data) do
    # Determine the address type based on the length
    case byte_size(data) do
      8 -> decode_v4(data)
      25 -> decode_v6(data)
    end
  end

  @doc """
  Encodes a TorCell.Relay.Connected into a binary.

  Returns a binary corresponding to the binary representation of that TorCell.
  """
  def encode(cell) do
    case tuple_size(cell.ip) do
      4 -> encode_v4(cell)
      16 -> encode_v6(cell)
    end
  end
end
