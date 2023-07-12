# SPDX-License-Identifier: ISC

defmodule TorCell.Netinfo do
  @enforce_keys [:time, :otheraddr, :myaddrs]
  defstruct time: nil,
            otheraddr: nil,
            myaddrs: nil

  @type t :: %TorCell.Netinfo{time: DateTime.t(), otheraddr: tuple(), myaddrs: list()}

  @spec fetch_addr(binary()) :: tuple()
  defp fetch_addr(payload) do
    remaining = payload
    <<atype, remaining::binary>> = remaining
    <<alen, remaining::binary>> = remaining
    <<aval::binary-size(alen), remaining::binary>> = remaining
    true = atype == 4 || atype == 6
    true = alen == 4 || alen == 16

    {List.to_tuple(:binary.bin_to_list(aval)), remaining}
  end

  @spec fetch_myaddrs(binary(), integer(), list()) :: {list(), binary()}
  defp fetch_myaddrs(payload, nmyaddrs, addrs) when nmyaddrs > 0 do
    {addr, remaining} = fetch_addr(payload)
    fetch_myaddrs(remaining, nmyaddrs - 1, addrs ++ [addr])
  end

  @spec fetch_myaddrs(binary(), integer(), list()) :: {list(), binary()}
  defp fetch_myaddrs(payload, _, addrs) do
    {addrs, payload}
  end

  @spec encode_addr(tuple()) :: binary()
  defp encode_addr(addr) do
    atype =
      case tuple_size(addr) do
        4 -> 4
        16 -> 6
      end

    <<atype, tuple_size(addr)>> <> :binary.list_to_bin(Tuple.to_list(addr))
  end

  @spec decode(binary()) :: TorCell.Netinfo
  def decode(payload) do
    remaining = payload
    <<time::32, remaining::binary>> = remaining
    time = DateTime.from_unix!(time)
    {otheraddr, remaining} = fetch_addr(remaining)
    <<nmyaddress, remaining::binary>> = remaining
    {myaddrs, _} = fetch_myaddrs(remaining, nmyaddress, [])

    %TorCell.Netinfo{time: time, otheraddr: otheraddr, myaddrs: myaddrs}
  end

  @spec encode(TorCell.Netinfo) :: binary()
  def encode(cell) do
    <<DateTime.to_unix(cell.time)::32>> <>
      encode_addr(cell.otheraddr) <>
      <<length(cell.myaddrs)>> <>
      Enum.join(Enum.map(cell.myaddrs, fn addr -> encode_addr(addr) end))
  end
end
