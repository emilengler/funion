# SPDX-License-Identifier: ISC

defmodule TorCell.AuthChallenge do
  defstruct challenge: nil,
            methods: nil

  defp decode_method(method) do
    case method do
      1 -> :rsa_sha256_tlssecret
      3 -> :ed25519_sha256_rfc5705
    end
  end

  defp decode_methods(methods) do
    # TODO: Enforce N_METHODS.
    <<_::16, methods::binary>> = methods

    for <<method::16 <- methods>> do
      decode_method(method)
    end
  end

  defp encode_method(method) do
    case method do
      :rsa_sha256_tlssecret -> <<1::16>>
      :ed25519_sha256_rfc5705 -> <<3::16>>
    end
  end

  defp encode_methods(methods) do
    Enum.join(Enum.map(methods, fn x -> encode_method(x) end))
  end

  @doc """
  Decodes the payload of an AUTH_CHALLENGE TorCell into its internal
  representation.

  Returns a TorCell.AuthChallenge with challenge being a 32-byte binary and
  methods an atom.
  """
  def decode(payload) do
    <<challenge::binary-size(32), payload::binary>> = payload

    %TorCell.AuthChallenge{
      challenge: challenge,
      methods: decode_methods(payload)
    }
  end

  @doc """
  Encodes a TorCell.AuthChallenge into a binary.

  Returns a binary corresponding to the payload of an AUTH_CHALLENGE TorCell.
  """
  def encode(cell) do
    cell.challenge <> <<length(cell.methods)::16>> <> encode_methods(cell.methods)
  end
end
