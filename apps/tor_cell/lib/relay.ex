# SPDX-License-Identifier: ISC

defmodule TorCell.Relay do
  @enforce_keys [:onion_skin]
  defstruct onion_skin: nil

  @type t :: %TorCell.Relay{onion_skin: binary()}

  @spec decode(binary()) :: t()
  def decode(payload) do
    <<onion_skin::binary-size(509)>> = payload
    %TorCell.Relay{onion_skin: onion_skin}
  end

  @spec encode(t()) :: binary()
  def encode(cell) do
    <<cell.onion_skin::binary-size(509)>>
  end
end
