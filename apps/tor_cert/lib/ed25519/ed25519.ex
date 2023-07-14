# SPDX-License-Identifier: ISC

defmodule TorCert.Ed25519 do
  @moduledoc """
  Provides features for handling with the Ed25519 certificates specified
  in `cert-spec.txt`.
  """
  @enforce_keys [
    :cert_type,
    :expiration_date,
    :cert_key_type,
    :certified_key,
    :extensions,
    :signature
  ]
  defstruct cert_type: nil,
            expiration_date: nil,
            cert_key_type: nil,
            certified_key: nil,
            extensions: nil,
            signature: nil

  @type t :: %TorCert.Ed25519{
          cert_type: cert_type(),
          expiration_date: DateTime.t(),
          cert_key_type: cert_key_type(),
          certified_key: binary(),
          extensions: list(TorCert.Ed25519.Extension.t()),
          signature: binary()
        }
  @type cert_type :: :ed25519_id_signing | :tls_ed25519_signing | :ed25519_auth_ed25519_signing
  @type cert_key_type :: :ed25519 | :sha256_x509

  @spec decode_cert_type(integer()) :: cert_type()
  defp decode_cert_type(cert_type) do
    case cert_type do
      0x04 -> :ed25519_signing_id
      0x05 -> :tls_ed25519_signing
      0x06 -> :ed25519_auth_ed25519_signing
    end
  end

  @spec decode_expiration_date(integer()) :: DateTime.t()
  defp decode_expiration_date(expiration_date) do
    expiration_date = expiration_date * 60 * 60
    DateTime.from_unix!(expiration_date)
  end

  @spec decode_cert_key_type(integer()) :: cert_key_type()
  defp decode_cert_key_type(cert_key_type) do
    case cert_key_type do
      0x01 -> :ed25519
      0x03 -> :sha256_x509
    end
  end

  @spec encode_cert_type(cert_type()) :: binary()
  defp encode_cert_type(cert_type) do
    case cert_type do
      :ed25519_signing_id -> <<0x04>>
      :tls_ed25519_signing -> <<0x05>>
      :ed25519_auth_ed25519_signing -> <<0x06>>
    end
  end

  @spec encode_expiration_date(DateTime.t()) :: binary()
  defp encode_expiration_date(expiration_date) do
    <<div(div(DateTime.to_unix(expiration_date), 60), 60)::32>>
  end

  @spec encode_cert_key_type(cert_key_type()) :: binary()
  defp encode_cert_key_type(cert_key_type) do
    case cert_key_type do
      :ed25519 -> <<0x01>>
      :sha256_x509 -> <<0x03>>
    end
  end

  @spec encode_extensions(list(TorCert.Ed25519.Extension.t())) :: binary()
  defp encode_extensions(extensions) do
    Enum.join(Enum.map(extensions, fn x -> TorCert.Ed25519.Extension.encode(x) end))
  end

  @spec fetch_extensions(list(TorCert.Ed25519.Extension.t()), integer(), binary()) ::
          {list(TorCert.Ed25519.Extension.t()), binary()}
  defp fetch_extensions(certs, n, data) when n > 0 do
    {cert, data} = TorCert.Ed25519.Extension.fetch(data)
    fetch_extensions(certs ++ [cert], n - 1, data)
  end

  defp fetch_extensions(certs, _, data) do
    {certs, data}
  end

  @doc """
  Decodes an Ed25519 into its internal representation.
  """
  @spec decode(binary()) :: t()
  def decode(data) do
    remaining = data
    <<1, remaining::binary>> = remaining
    <<cert_type, remaining::binary>> = remaining
    <<expiration_date::32, remaining::binary>> = remaining
    <<cert_key_type, remaining::binary>> = remaining
    <<certified_key::binary-size(32), remaining::binary>> = remaining
    <<n_extensions, remaining::binary>> = remaining
    {extensions, remaining} = fetch_extensions([], n_extensions, remaining)
    <<signature::binary-size(64), _::binary>> = remaining

    %TorCert.Ed25519{
      cert_type: decode_cert_type(cert_type),
      expiration_date: decode_expiration_date(expiration_date),
      cert_key_type: decode_cert_key_type(cert_key_type),
      certified_key: certified_key,
      extensions: extensions,
      signature: signature
    }
  end

  @doc """
  Encodes an Ed25519 certificate into a binary

  Returns a binary corresponding to the certificate.
  """
  @spec encode(t()) :: binary()
  def encode(cert) do
    <<1>> <>
      encode_cert_type(cert.cert_type) <>
      encode_expiration_date(cert.expiration_date) <>
      encode_cert_key_type(cert.cert_key_type) <>
      <<cert.certified_key::binary-size(32)>> <>
      <<length(cert.extensions)>> <>
      encode_extensions(cert.extensions) <>
      <<cert.signature::binary-size(64)>>
  end

  @doc """
  Validates if a certificate is properly signed.
  """
  @spec is_valid?(t(), binary(), DateTime.t()) :: boolean()
  def is_valid?(cert, key, time \\ DateTime.utc_now()) do
    if DateTime.compare(time, cert.expiration_date) == :gt do
      false
    else
      # Encode the certificate with the signature removed
      encoded = encode(cert)
      len = byte_size(encoded) - 64
      <<encoded::binary-size(len), _::binary>> = encoded

      :crypto.verify(:eddsa, :none, encoded, cert.signature, [key, :ed25519])
    end
  end
end
