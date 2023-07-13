# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extend2.Spec do
  @enforce_keys [:lstype, :lspec]
  defstruct lstype: nil,
            lspec: nil

  @type t :: %TorCell.RelayCell.Extend2.Spec{lstype: lstype(), lspec: lspec()}
  @type lstype :: :tls_over_tcp4 | :tls_over_tcp6 | :legacy_identity | :ed25519_identity
  @type lspec ::
          TorCell.RelayCell.Extend2.Spec.TlsOverTcp4.t()
          | TorCell.RelayCell.Extend2.Spec.TlsOverTcp6.t()
          | TorCell.RelayCell.Extend2.Spec.LegacyIdentity.t()
          | TorCell.RelayCell.Extend2.Spec.Ed25519Identity.t()

  @spec decode_lstype(integer()) :: lstype()
  defp decode_lstype(lstype) do
    case lstype do
      0 -> :tls_over_tcp4
      1 -> :tls_over_tcp6
      2 -> :legacy_identity
      3 -> :ed25519_identity
    end
  end

  @spec decode_lspec(lstype(), binary()) :: lspec()
  defp decode_lspec(lstype, lspec) do
    case lstype do
      :tls_over_tcp4 -> TorCell.RelayCell.Extend2.Spec.TlsOverTcp4.decode(lspec)
      :tls_over_tcp6 -> TorCell.RelayCell.Extend2.Spec.TlsOverTcp6.decode(lspec)
      :legacy_identity -> TorCell.RelayCell.Extend2.Spec.LegacyIdentity.decode(lspec)
      :ed25519_identity -> TorCell.RelayCell.Extend2.Spec.Ed25519Identity.decode(lspec)
    end
  end

  @spec encode_lstype(lstype()) :: binary()
  defp encode_lstype(lstype) do
    case lstype do
      :tls_over_tcp4 -> <<0>>
      :tls_over_tcp6 -> <<1>>
      :legacy_identity -> <<2>>
      :ed25519_identity -> <<3>>
    end
  end

  @spec encode_lspec(lstype(), lspec()) :: binary()
  defp encode_lspec(lstype, lspec) do
    case lstype do
      :tls_over_tcp4 -> TorCell.RelayCell.Extend2.Spec.TlsOverTcp4.encode(lspec)
      :tls_over_tcp6 -> TorCell.RelayCell.Extend2.Spec.TlsOverTcp6.encode(lspec)
      :legacy_identity -> TorCell.RelayCell.Extend2.Spec.LegacyIdentity.encode(lspec)
      :ed25519_identity -> TorCell.RelayCell.Extend2.Spec.Ed25519Identity.encode(lspec)
    end
  end

  @spec fetch(binary()) :: {t(), binary()}
  def fetch(data) do
    remaining = data
    <<lstype, remaining::binary>> = remaining
    <<lslen, remaining::binary>> = remaining
    <<lspec::binary-size(lslen), remaining::binary>> = remaining

    lstype = decode_lstype(lstype)
    lspec = decode_lspec(lstype, lspec)

    {%TorCell.RelayCell.Extend2.Spec{lstype: lstype, lspec: lspec}, remaining}
  end

  @spec encode(t()) :: binary()
  def encode(spec) do
    encoded = encode_lspec(spec.lstype, spec.lspec)
    encode_lstype(spec.lstype) <> <<byte_size(encoded)>> <> encoded
  end
end
