# SPDX-License-Identifier: ISC

defmodule TorCell.Created2 do
  @enforce_keys [:hdata]
  defstruct hdata: nil

  @type t :: %TorCell.Created2{hdata: binary()}

  @spec decode(binary()) :: TorCell.Created2
  def decode(payload) do
    remaining = payload
    <<hlen::16, remaining::binary>> = remaining
    <<hdata::binary-size(hlen), _::binary>> = remaining

    %TorCell.Created2{hdata: hdata}
  end

  @spec encode(TorCell.Created2) :: binary()
  def encode(cell) do
    <<byte_size(cell.hdata)::16>> <> cell.hdata
  end
end
