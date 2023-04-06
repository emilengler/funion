defmodule TorCert.Ed25519.Extension do
  @moduledoc """
  Internal representation of the extensions described in Ed25519 certificates
  in `cert-spec.txt`.

  This module only implements the parts of the specification needed to parse
  the Signed-with-ed25519-key extension. This is intentional.
  """
  defstruct type: nil,
            flags: nil,
            data: nil

  defp decode_flags(flags) do
    case flags do
      0 -> nil
      1 -> :affects_validation
    end
  end

  defp encode_flags(flags) do
    case flags do
      nil -> <<0>>
      :affects_validation -> <<1>>
    end
  end

  @doc """
  Fetches the first extension in a binary.

  Returns the internal representation of the found extension, alongside
  the remaining data.
  """
  def fetch(data) do
    <<32::16, data::binary>> = data
    <<0x04::8, data::binary>> = data
    <<flags::8, data::binary>> = data
    <<ext_data::binary-size(32), data::binary>> = data

    {
      %TorCert.Ed25519.Extension{
        type: :signed_with_ed25519_key,
        flags: decode_flags(flags),
        data: ext_data
      },
      data
    }
  end

  @doc """
  Encodes an extension into a binary.

  Returns a binary corresponding to the binary representation of the extensions.
  """
  def encode(extension) do
    <<32::16>> <> <<0x04>> <> encode_flags(extension.flags) <> extension.data
  end
end
