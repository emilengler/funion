# SPDX-License-Identifier: ISC

defmodule TorCert.Ed25519.Extension do
  @moduledoc """
  Internal representation of the extensions described in Ed25519 certificates
  in `cert-spec.txt`.

  This module only implements the parts of the specification needed to parse
  the Signed-with-ed25519-key extension. This is intentional.
  """
  @enforce_keys [:type, :flags, :data]
  defstruct type: nil,
            flags: nil,
            data: nil

  @type t :: %TorCert.Ed25519.Extension{
          type: type(),
          flags: flags(),
          data: binary()
        }
  @type type :: :signed_with_ed25519_key
  @type flags :: nil | :affects_validation

  @spec decode_flags(integer()) :: flags()
  defp decode_flags(flags) do
    case flags do
      0 -> nil
      1 -> :affects_validation
    end
  end

  @spec encode_flags(flags()) :: binary()
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
  @spec fetch(binary()) :: {t(), binary()}
  def fetch(data) do
    <<32::16, data::binary>> = data
    <<0x04, data::binary>> = data
    <<flags, data::binary>> = data
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
  @spec encode(t()) :: binary()
  def encode(extension) do
    <<32::16>> <> <<0x04>> <> encode_flags(extension.flags) <> extension.data
  end
end
