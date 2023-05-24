# SPDX-License-Identifier: ISC

defmodule TorCert.RsaEd25519 do
  @moduledoc """
  Provides features for handling with the RSA->Ed25519 cross-certificates
  specified in `cert-spec.txt`.
  """
  defstruct ed25519_key: nil,
            expiration_date: nil,
            signature: nil

  @doc """
  Fetches the first RSA->Ed25519 cross-certificate in a binary.

  Returns the internal representation of the found certificate, alongside
  the remaining data.
  """
  def fetch(data) do
    <<ed25519_key::binary-size(32), data::binary>> = data
    <<expiration_date::32, data::binary>> = data
    <<siglen::8, data::binary>> = data
    <<signature::binary-size(siglen), data::binary>> = data

    {
      %TorCert.RsaEd25519{
        ed25519_key: ed25519_key,
        expiration_date: DateTime.from_unix!(expiration_date),
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
      <<DateTime.to_unix(cert.expiration_date)::32>> <>
      <<byte_size(cert.signature)>> <>
      cert.signature
  end
end
