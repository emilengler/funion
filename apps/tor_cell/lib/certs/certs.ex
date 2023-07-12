# SPDX-License-Identifier: ISC

defmodule TorCell.Certs do
  @enforce_keys [:certs]
  defstruct certs: nil

  @type t :: %TorCell.Certs{certs: certs()}
  @type certs :: list(cert())
  @type cert :: TorCell.Certs.Cert

  @spec decode_certs(binary(), integer(), certs()) :: certs()
  defp decode_certs(payload, n, certs) when n > 0 do
    {cert, remaining} = TorCell.Certs.Cert.fetch(payload)
    decode_certs(remaining, n - 1, certs ++ [cert])
  end

  @spec decode_certs(binary(), integer(), certs()) :: certs()
  defp decode_certs(_, _, certs) do
    certs
  end

  @spec decode(binary()) :: TorCell.Certs
  def decode(payload) do
    remaining = payload
    <<n, remaining::binary>> = remaining
    %TorCell.Certs{certs: decode_certs(remaining, n, [])}
  end

  @spec encode(TorCell.Certs) :: binary()
  def encode(cell) do
    <<length(cell.certs)>> <>
      Enum.join(Enum.map(cell.certs, fn x -> TorCell.Certs.Cert.encode(x) end))
  end
end
