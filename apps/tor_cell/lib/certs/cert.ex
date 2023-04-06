defmodule TorCell.Certs.Cert do
  defstruct type: nil,
            cert: nil

  defp decode_type(type) do
    case type do
      1 -> :rsa_link
      2 -> :rsa_id
      3 -> :rsa_auth
      4 -> :ed25519_id_signing
      5 -> :ed25519_signing_link
      6 -> :ed25519_signing_auth
      7 -> :rsa_ed25519_cross_cert
    end
  end

  defp decode_cert(type, cert) do
    case type do
      :rsa_link -> decode_cert_x509(cert)
      :rsa_id -> decode_cert_x509(cert)
      :rsa_auth -> decode_cert_x509(cert)
      :ed25519_id_signing -> decode_cert_tor_ed25519(cert)
      :ed25519_signing_link -> decode_cert_tor_ed25519(cert)
      :ed25519_signing_auth -> decode_cert_tor_ed25519(cert)
      :rsa_ed25519_cross_cert -> decode_cert_tor_rsa_ed25519(cert)
    end
  end

  defp decode_cert_tor_ed25519(cert) do
    {cert, _} = TorCert.Ed25519.fetch(cert)
    cert
  end

  defp decode_cert_tor_rsa_ed25519(cert) do
    {cert, _} = TorCert.RsaEd25519.fetch(cert)
    cert
  end

  defp decode_cert_x509(cert) do
    # TODO
    cert
  end

  defp encode_type(type) do
    case type do
      :rsa_link -> <<1>>
      :rsa_id -> <<2>>
      :rsa_auth -> <<3>>
      :ed25519_id_signing -> <<4>>
      :ed25519_signing_link -> <<5>>
      :ed25519_signing_auth -> <<6>>
      :rsa_ed25519_cross_cert -> <<7>>
    end
  end

  defp encode_cert(type, cert) do
    case type do
      :rsa_link -> encode_cert_x509(cert)
      :rsa_id -> encode_cert_x509(cert)
      :rsa_auth -> encode_cert_x509(cert)
      :ed25519_id_signing -> TorCert.Ed25519.encode(cert)
      :ed25519_signing_link -> TorCert.Ed25519.encode(cert)
      :ed25519_signing_auth -> TorCert.Ed25519.encode(cert)
      :rsa_ed25519_cross_cert -> TorCert.RsaEd25519.encode(cert)
    end
  end

  defp encode_cert_x509(_) do
    # TODO
    <<>>
  end

  @doc """
  Encodes the TorCell.Certs.Cert into a binary.

  Returns a binary corresponding to the payload of a certificate inside
  a CERTS TorCell.
  """
  def encode(cert) do
    # TODO: Check for an overflow here
    encode_type(cert.type) <> <<byte_size(cert.cert)::16>> <> encode_cert(cert.type, cert.cert)
  end

  @doc """
  Fetches the first certificate in a binary.

  Returns the internal representation of the found certificate, alongside the
  remaining data.
  """
  def fetch(payload) do
    <<type, payload::binary>> = payload
    <<clen::16, payload::binary>> = payload
    <<cert::binary-size(clen), payload::binary>> = payload

    type = decode_type(type)

    {
      %TorCell.Certs.Cert{
        type: type,
        cert: decode_cert(type, cert)
      },
      payload
    }
  end
end
