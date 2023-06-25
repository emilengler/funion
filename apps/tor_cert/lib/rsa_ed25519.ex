# SPDX-License-Identifier: ISC

defmodule TorCert.RsaEd25519 do
  @moduledoc """
  Provides features for handling with the RSA->Ed25519 cross-certificates
  specified in `cert-spec.txt`.
  """
  defstruct ed25519_key: nil,
            expiration_date: nil,
            signature: nil

  defp decode_expiration_date(expiration_date) do
    expiration_date = expiration_date * 60 * 60
    DateTime.from_unix!(expiration_date)
  end

  defp encode_expiration_date(expiration_date) do
    <<div(div(DateTime.to_unix(expiration_date), 60), 60)::32>>
  end

  @doc """
  Fetches the first RSA->Ed25519 cross-certificate in a binary.

  Returns the internal representation of the found certificate, alongside
  the remaining data.
  """
  def fetch(data) do
    <<ed25519_key::binary-size(32), data::binary>> = data
    <<expiration_date::32, data::binary>> = data
    expiration_date = decode_expiration_date(expiration_date)
    <<siglen::8, data::binary>> = data
    <<signature::binary-size(siglen), data::binary>> = data

    {
      %TorCert.RsaEd25519{
        ed25519_key: ed25519_key,
        expiration_date: expiration_date,
        signature: signature
      },
      data
    }
  end

  @doc """
  Encodes an RSA->Ed25519 cross-certificate into a binary.

  Returns a binary corresponding to the certificate.
  """
  def encode(cert) do
    <<cert.ed25519_key::binary-size(32)>> <>
      encode_expiration_date(cert.expiration_date) <>
      <<byte_size(cert.signature)>> <>
      cert.signature
  end
end
