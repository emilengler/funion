defmodule TorCell.Netinfo do
  defstruct time: nil,
            otheraddr: nil,
            myaddrs: nil

  defp encode_addr(addr) do
    atype =
      case length(addr) do
        4 -> 0x04
        16 -> 0x06
      end

    <<atype>> <> <<length(addr)>> <> Enum.join(Enum.map(addr, fn x -> <<x>> end))
  end

  defp fetch_addr(payload) do
    # TODO: Enforce the type
    <<_, payload::binary>> = payload
    <<alen, payload::binary>> = payload
    <<aval::binary-size(alen), payload::binary>> = payload
    # TODO: Parse to an ACTUAL IP data type
    {:binary.bin_to_list(aval), payload}
  end

  defp fetch_myaddrs(addrs, n, payload) when n > 0 do
    {addr, payload} = fetch_addr(payload)
    fetch_myaddrs(addrs ++ [addr], n - 1, payload)
  end

  defp fetch_myaddrs(addrs, _, payload) do
    {addrs, payload}
  end

  defp fetch_myaddrs(payload) do
    <<n, payload::binary>> = payload
    fetch_myaddrs([], n, payload)
  end

  @doc """
  Decodes the payload of a NETINFO TorCell into its internal representation.

  Returns a TorCell.Netinfo with the fields set accordingly.
  """
  def decode(payload) do
    <<time::32, payload::binary>> = payload
    {otheraddr, payload} = fetch_addr(payload)
    {myaddrs, _} = fetch_myaddrs(payload)

    %TorCell.Netinfo{
      time: DateTime.from_unix!(time),
      otheraddr: otheraddr,
      myaddrs: myaddrs
    }
  end

  @doc """
  Encodes a TorCell.Netinfo into a binary.

  Returns a binary corresponding to the payload of a NETINFO TorCell.
  """
  def encode(cell) do
    <<DateTime.to_unix(cell.time)::32>> <>
      encode_addr(cell.otheraddr) <>
      <<length(cell.myaddrs)>> <>
      Enum.join(Enum.map(cell.myaddrs, fn x -> encode_addr(x) end))
  end
end
