# SPDX-License-Identifier: ISC

defmodule TorCell.Authenticate do
  defstruct type: nil,
            auth: nil

  defp decode_type(type) do
    case type do
      1 -> :rsa_sha256_tlssecret
      3 -> :ed25519_sha256_rfc5705
    end
  end

  defp decode_auth(auth, type) do
    case type do
      :rsa_sha256_tlssecret -> TorCell.Authenticate.RsaSha256Tlssecret.decode(auth)
      :ed25519_sha256_rfc5705 -> TorCell.Authenticate.Ed25519Sha256Rfc5705.decode(auth)
    end
  end

  defp encode_type(type) do
    case type do
      :rsa_sha256_tlssecret -> <<1::16>>
      :ed25519_sha256_rfc5705 -> <<3::16>>
    end
  end

  defp encode_auth(auth, type) do
    case type do
      :rsa_sha256_tlssecret -> TorCell.Authenticate.RsaSha256Tlssecret.encode(auth)
      :ed25519_sha256_rfc5705 -> TorCell.Authenticate.Ed25519Sha256Rfc5705.encode(auth)
    end
  end

  @doc """
  Decodes the payload of an AUTHENTICATE TorCell into its internal
  representation.

  Returns a TorCell.Authenticate with type being an atom and
  auth either an TorCell.Authenticate.RsaSha256Tlssecret or
  TorCell.Authenticate.Ed25519Sha256Rfc5075.
  """
  def decode(payload) do
    <<type::16, payload::binary>> = payload
    <<len::16, payload::binary>> = payload
    <<auth::binary-size(len), _::binary>> = payload

    type = decode_type(type)
    auth = decode_auth(auth, type)

    %TorCell.Authenticate{
      type: type,
      auth: auth
    }
  end

  @doc """
  Encodes a TorCell.Authenticate into a binary.

  Returns a binary corresponding to the payloaf of an AUTHENTICATE TorCell.
  """
  def encode(cell) do
    type = encode_type(cell.type)
    auth = encode_auth(cell.auth, cell.type)
    type <> <<byte_size(auth)::16>> <> auth
  end
end
