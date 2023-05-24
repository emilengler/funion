# SPDX-License-Identifier: ISC

defmodule TorCell.Certs do
  defstruct certs: nil

  defp fetch_certs(certs, n, payload) when n > 0 do
    {cert, payload} = TorCell.Certs.Cert.fetch(payload)
    fetch_certs(certs ++ [cert], n - 1, payload)
  end

  defp fetch_certs(certs, _, payload) do
    {certs, payload}
  end

  @doc """
  Decodes the payload of a CERTS TorCell into its internal representation.

  Returns a TorCell.Certs with certs being a list of all certificates.
  """
  def decode(payload) do
    <<n, payload::binary>> = payload
    {certs, _} = fetch_certs([], n, payload)

    %TorCell.Certs{
      certs: certs
    }
  end

  @doc """
  Encodes a TorCell.Certs into a binary.

  Returns a binary corresponding to the payload of a CERTS TorCell.
  """
  def encode(cell) do
    # TODO: Check for overflow
    <<length(cell.certs)>> <>
      Enum.join(Enum.map(cell.certs, fn x -> TorCell.Certs.Cert.encode(x) end))
  end
end
