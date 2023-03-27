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

  defp encode_type(type) do
    case type do
      :rsa_link -> <<1::8>>
      :rsa_id -> <<2::8>>
      :rsa_auth -> <<3::8>>
      :ed25519_id_signing -> <<4::8>>
      :ed25519_signing_link -> <<5::8>>
      :ed25519_signing_auth -> <<6::8>>
      :rsa_ed25519_cross_cert -> <<7::8>>
    end
  end

  @doc """
  Encodes the TorCell.Certs.Cert into a binary.

  Returns a binary corresponding to the payload of a certificate inside
  a CERTS TorCell.
  """
  def encode(cert) do
    # TODO: Check for an overflow here
    encode_type(cert.type) <> <<byte_size(cert.cert)::16>> <> cert.cert
  end

  @doc """
  Fetches the first certificate in a binary.

  Returns the internal representation of the found certificate, alongside the
  remaining data.
  """
  def fetch(payload) do
    <<type::8, payload::binary>> = payload
    <<clen::16, payload::binary>> = payload
    <<cert::binary-size(clen), payload::binary>> = payload

    {
      %TorCell.Certs.Cert{
        type: decode_type(type),
        cert: cert
      },
      payload
    }
  end
end
