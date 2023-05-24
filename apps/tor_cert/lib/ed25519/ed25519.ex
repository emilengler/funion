# SPDX-License-Identifier: ISC

defmodule TorCert.Ed25519 do
  @moduledoc """
  Provides features for handling with the Ed25519 certificates specified
  in `cert-spec.txt`.
  """
  defstruct cert_type: nil,
            expiration_date: nil,
            cert_key_type: nil,
            certified_key: nil,
            extensions: nil,
            signature: nil

  defp decode_cert_type(cert_type) do
    case cert_type do
      0x04 -> :ed25519_signing_id
      0x05 -> :tls_ed25519_signing
      0x06 -> :ed25519_auth_ed25519_signing
    end
  end

  defp decode_cert_key_type(cert_key_type) do
    case cert_key_type do
      0x01 -> :ed25519
      0x03 -> :sha256_x509
    end
  end

  defp encode_cert_type(cert_type) do
    case cert_type do
      :ed25519_signing_id -> <<0x04>>
      :tls_ed25519_signing -> <<0x05>>
      :ed25519_auth_ed25519_signing -> <<0x06>>
    end
  end

  defp encode_cert_key_type(cert_key_type) do
    case cert_key_type do
      :ed25519 -> <<0x01>>
      :sha256_x509 -> <<0x03>>
    end
  end

  defp encode_extensions(extensions) do
    Enum.join(Enum.map(extensions, fn x -> TorCert.Ed25519.Extension.encode(x) end))
  end

  defp fetch_extensions(certs, n, data) when n > 0 do
    {cert, data} = TorCert.Ed25519.Extension.fetch(data)
    fetch_extensions(certs ++ [cert], n - 1, data)
  end

  defp fetch_extensions(certs, _, data) do
    {certs, data}
  end

  @doc """
  Fetches the first Ed25519 certificate in a binary.

  Returns the internal representation of the found certificate, alongside
  the remaining data.
  """
  def fetch(data) do
    # TODO: Consider fetching the version?
    <<1::8, data::binary>> = data
    <<cert_type::8, data::binary>> = data
    <<expiration_date::32, data::binary>> = data
    <<cert_key_type::8, data::binary>> = data
    <<certified_key::binary-size(32), data::binary>> = data
    <<n_extensions::8, data::binary>> = data
    {extensions, data} = fetch_extensions([], n_extensions, data)
    <<signature::binary-size(64), data::binary>> = data

    {
      %TorCert.Ed25519{
        cert_type: decode_cert_type(cert_type),
        expiration_date: DateTime.from_unix!(expiration_date),
        cert_key_type: decode_cert_key_type(cert_key_type),
        certified_key: certified_key,
        extensions: extensions,
        signature: signature
      },
      data
    }
  end

  @doc """
  Encodes an Ed25519 certificate into a binary

  Returns a binary corresponding to the certficiate.
  """
  def encode(cert) do
    <<1>> <>
      encode_cert_type(cert.cert_type) <>
      <<DateTime.to_unix(cert.expiration_date)::32>> <>
      encode_cert_key_type(cert.cert_key_type) <>
      <<cert.certified_key::binary-size(32)>> <>
      <<length(cert.extensions)>> <>
      encode_extensions(cert.extensions) <>
      <<cert.signature::binary-size(64)>>
  end
end
