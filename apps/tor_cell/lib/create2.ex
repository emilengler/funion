# SPDX-License-Identifier: ISC

defmodule TorCell.Create2 do
  @enforce_keys [:htype, :hdata]
  defstruct htype: nil,
            hdata: nil

  @type t :: %TorCell.Create2{htype: htype(), hdata: binary()}
  @type htype :: :ntor

  @spec decode(binary()) :: TorCell.Create2
  def decode(payload) do
    remaining = payload
    <<0x02::16, remaining::binary>> = remaining
    <<hlen::16, remaining::binary>> = remaining
    <<hdata::binary-size(hlen), _::binary>> = remaining

    %TorCell.Create2{htype: :ntor, hdata: hdata}
  end

  @spec encode(TorCell.Create2) :: binary()
  def encode(cell) do
    <<0x02::16, byte_size(cell.hdata)::16>> <> cell.hdata
  end
end
