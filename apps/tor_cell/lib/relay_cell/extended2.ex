# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extended2 do
  @enforce_keys [:hdata]
  defstruct hdata: nil

  @type t :: %TorCell.RelayCell.Extended2{hdata: binary()}

  @spec decode(binary()) :: t()
  def decode(payload) do
    remaining = payload
    <<hlen::16, remaining::binary>> = remaining
    <<hdata::binary-size(hlen), _::binary>> = remaining

    %TorCell.RelayCell.Extended2{hdata: hdata}
  end

  @spec encode(t()) :: binary()
  def encode(cell) do
    <<byte_size(cell.hdata)::16>> <> cell.hdata
  end
end
