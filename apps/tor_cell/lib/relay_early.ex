# SPDX-License-Identifier: ISC

defmodule TorCell.RelayEarly do
  @enforce_keys [:onion_skin]
  defstruct onion_skin: nil

  @type t :: %TorCell.RelayEarly{onion_skin: binary()}

  @spec decode(binary()) :: TorCell.RelayEarly
  def decode(payload) do
    <<onion_skin::binary-size(509)>> = payload
    %TorCell.RelayEarly{onion_skin: onion_skin}
  end

  @spec encode(TorCell.RelayEarly) :: binary()
  def encode(cell) do
    <<cell.onion_skin::binary-size(509)>>
  end
end
