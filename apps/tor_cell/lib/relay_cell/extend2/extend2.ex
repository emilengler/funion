# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extend2 do
  defstruct specs: nil,
            type: nil,
            data: nil

  defp fetch_specs(specs, n, payload) when n > 0 do
    {spec, payload} = TorCell.RelayCell.Extend2.Spec.fetch(payload)
    fetch_specs(specs ++ [spec], n - 1, payload)
  end

  defp fetch_specs(specs, _, payload) do
    {specs, payload}
  end

  # TODO: Document this
  def decode(payload) do
    <<nspec, payload::binary>> = payload
    {specs, payload} = fetch_specs([], nspec, payload)
    <<0x02::16, payload::binary>> = payload
    <<len::16, payload::binary>> = payload
    <<data::binary-size(len), _::binary>> = payload

    %TorCell.RelayCell.Extend2{specs: specs, type: :ntor, data: data}
  end

  # TODO: Encode this
  def encode(cell) do
    <<length(cell.specs)>> <>
      Enum.join(Enum.map(cell.specs, fn x -> TorCell.RelayCell.Extend2.Spec.encode(x) end)) <>
      <<0x02::16>> <>
      <<byte_size(cell.data)::16>> <>
      cell.data
  end
end
