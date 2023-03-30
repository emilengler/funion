defmodule TorCell.Authenticate do
  defstruct auth_type: nil,
            authentication: nil

  defp decode_auth_type(type) do
    case type do
      1 -> :rsa_sha256_tlssecret
      3 -> :ed25519_sha256_rfc5705
    end
  end

  defp decode_authentication(auth, type) do
    case type do
      :rsa_sha256_tlssecret -> TorCell.Authenticate.RsaSha256Tlssecret.decode(auth)
      :ed25519_sha256_rfc5705 -> TorCell.Authenticate.Ed25519Sha256Rfc5705.decode(auth)
    end
  end

  defp encode_auth_type(type) do
    case type do
      :rsa_sha256_tlssecret -> <<1::16>>
      :ed25519_sha256_rfc5705 -> <<3::16>>
    end
  end

  defp encode_authentication(auth, type) do
    case type do
      :rsa_sha256_tlssecret -> TorCell.Authenticate.RsaSha256Tlssecret.encode(auth)
      :ed25519_sha256_rfc5705 -> TorCell.Authenticate.Ed25519Sha256Rfc5705.encode(auth)
    end
  end

  @doc """
  Decodes the payload of an AUTHENTICATE TorCell into its internal
  representation.

  Returns a TorCell.Authenticate with auth_type being an atom and
  authentication either an TorCell.Authenticate.RsaSha256Tlssecret or
  TorCell.Authenticate.Ed25519Sha256Rfc5075.
  """
  def decode(payload) do
    <<type::16, payload::binary>> = payload
    <<len::16, payload::binary>> = payload
    <<auth::binary-size(len), _::binary>> = payload

    type = decode_auth_type(type)
    auth = decode_authentication(auth, type)

    %TorCell.Authenticate{
      auth_type: type,
      authentication: auth
    }
  end

  @doc """
  Encodes a TorCell.Authenticate into a binary.

  Returns a binary corresponding to the payloaf of an AUTHENTICATE TorCell.
  """
  def encode(cell) do
    auth_type = encode_auth_type(cell.auth_type)
    authentication = encode_authentication(cell.authentication, cell.auth_type)
    <<auth_type::16>> <> <<length(authentication)::16>> <> <<authentication>>
  end
end
