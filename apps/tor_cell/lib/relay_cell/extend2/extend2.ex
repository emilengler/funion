# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extend2 do
  @enforce_keys [:specs, :htype, :hdata]
  defstruct specs: nil,
            htype: nil,
            hdata: nil

  @type t :: %TorCell.RelayCell.Extend2{specs: specs(), htype: htype(), hdata: binary()}
  @type specs :: list(spec())
  @type spec :: TorCell.RelayCell.Extend2.Spec

  @type htype :: :ntor

  @spec fetch_specs(binary(), integer(), specs()) :: {specs(), binary()}
  defp fetch_specs(data, n, specs) when n > 0 do
    {spec, remaining} = TorCell.RelayCell.Extend2.Spec.fetch(data)
    fetch_specs(remaining, n - 1, specs ++ [spec])
  end

  @spec fetch_specs(binary(), integer(), specs()) :: {specs(), binary()}
  defp fetch_specs(remaining, _, specs) do
    {specs, remaining}
  end

  @spec decode(binary()) :: TorCell.RelayCell.Extend2
  def decode(data) do
    remaining = data
    <<nspec, remaining::binary>> = remaining
    {specs, remaining} = fetch_specs(remaining, nspec, [])
    <<0x02::16, remaining::binary>> = remaining
    <<hlen::16, remaining::binary>> = remaining
    <<hdata::binary-size(hlen), _::binary>> = remaining

    %TorCell.RelayCell.Extend2{specs: specs, htype: :ntor, hdata: hdata}
  end

  @spec encode(TorCell.RelayCell.Extend2) :: binary()
  def encode(cell) do
    <<length(cell.specs)>> <>
      Enum.join(Enum.map(cell.specs, fn x -> TorCell.RelayCell.Extend2.Spec.encode(x) end)) <>
      <<0x02::16, byte_size(cell.hdata)::16>> <> cell.hdata
  end
end
