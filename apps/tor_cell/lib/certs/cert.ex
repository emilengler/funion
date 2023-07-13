# SPDX-License-Identifier: ISC

defmodule TorCell.Certs.Cert do
  @enforce_keys [:cert_type, :certificate]
  defstruct cert_type: nil,
            certificate: nil

  @type t :: %TorCell.Certs.Cert{cert_type: cert_type(), certificate: certificate()}
  @type cert_type() ::
          :rsa_link
          | :rsa_id
          | :rsa_auth
          | :ed25519_id_signing
          | :ed25519_signing_link
          | :ed25510_signing_auth
          | :rsa_ed25519_cross_cert
  @type certificate :: binary() | TorCert.Ed25519.t() | TorCert.RsaEd25519.t()

  @spec decode_cert_type(integer()) :: cert_type()
  defp decode_cert_type(cert_type) do
    case cert_type do
      1 -> :rsa_link
      2 -> :rsa_id
      3 -> :rsa_auth
      4 -> :ed25519_id_signing
      5 -> :ed25519_signing_link
      6 -> :ed25519_signing_auth
      7 -> :rsa_ed25519_cross_cert
    end
  end

  @spec decode_certificate(cert_type(), binary()) :: certificate()
  defp decode_certificate(cert_type, certificate) do
    case cert_type do
      :rsa_link -> certificate
      :rsa_id -> certificate
      :rsa_auth -> certificate
      :ed25519_id_signing -> TorCert.Ed25519.decode(certificate)
      :ed25519_signing_link -> TorCert.Ed25519.decode(certificate)
      :ed25519_signing_auth -> TorCert.Ed25519.decode(certificate)
      :rsa_ed25519_cross_cert -> TorCert.RsaEd25519.decode(certificate)
    end
  end

  @spec encode_cert_type(cert_type()) :: binary()
  defp encode_cert_type(cert_type) do
    case cert_type do
      :rsa_link -> <<1>>
      :rsa_id -> <<2>>
      :rsa_auth -> <<3>>
      :ed25519_id_signing -> <<4>>
      :ed25519_signing_link -> <<5>>
      :ed25519_signing_auth -> <<6>>
      :rsa_ed25519_cross_cert -> <<7>>
    end
  end

  @spec encode_certificate(cert_type(), certificate()) :: binary()
  defp encode_certificate(cert_type, certificate) do
    case cert_type do
      :rsa_link -> :public_key.pkix_encode(:Certificate, certificate, :plain)
      :rsa_id -> :public_key.pkix_encode(:Certificate, certificate, :plain)
      :rsa_auth -> :public_key.pkix_encode(:Certificate, certificate, :plain)
      :ed25519_id_signing -> TorCert.Ed25519.encode(certificate)
      :ed25519_signing_link -> TorCert.Ed25519.encode(certificate)
      :ed25519_signing_auth -> TorCert.Ed25519.encode(certificate)
      :rsa_ed25519_cross_cert -> TorCert.RsaEd25519.encode(certificate)
    end
  end

  @spec fetch(binary()) :: {t(), binary()}
  def fetch(payload) do
    remaining = payload
    <<cert_type, remaining::binary>> = remaining
    <<clen::16, remaining::binary>> = remaining
    <<certificate::binary-size(clen), remaining::binary>> = remaining

    cert_type = decode_cert_type(cert_type)
    certificate = decode_certificate(cert_type, certificate)

    {%TorCell.Certs.Cert{cert_type: cert_type, certificate: certificate}, remaining}
  end

  @spec encode(t()) :: binary()
  def encode(cert) do
    encoded = encode_certificate(cert.cert_type, cert.certificate)
    encode_cert_type(cert.cert_type) <> <<byte_size(encoded)::16>> <> encoded
  end
end
