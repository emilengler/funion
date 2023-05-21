defmodule TorCell.Relay.Extend2.Spec do
  defstruct type: nil,
            spec: nil

  def decode_type(type) do
    case type do
      0 -> :tls_over_tcp4
      1 -> :tls_over_tcp6
      2 -> :legacy_identity
      3 -> :ed25519_identity
    end
  end

  defp decode_spec(type, spec) do
    case type do
      :tls_over_tcp4 -> TorCell.Relay.Extend2.Spec.TlsOverTcp4.decode(spec)
      :tls_over_tcp6 -> TorCell.Relay.Extend2.Spec.TlsOverTcp6.decode(spec)
      :legacy_identity -> TorCell.Relay.Extend2.Spec.LegacyIdentity.decode(spec)
      :ed25519_identity -> TorCell.Relay.Extend2.Spec.Ed25519Identity.decode(spec)
    end
  end

  defp encode_type(type) do
    case type do
      :tls_over_tcp4 -> <<0>>
      :tls_over_tcp6 -> <<1>>
      :legacy_identity -> <<2>>
      :ed25519_identity -> <<3>>
    end
  end

  defp encode_spec(type, spec) do
    case type do
      :tls_over_tcp4 -> TorCell.Relay.Extend2.Spec.TlsOverTcp4.encode(spec)
      :tls_over_tcp6 -> TorCell.Relay.Extend2.Spec.TlsOverTcp6.encode(spec)
      :legacy_identity -> TorCell.Relay.Extend2.Spec.LegacyIdentity.encode(spec)
      :ed25519_identity -> TorCell.Relay.Extend2.Spec.Ed25519Identity.encode(spec)
    end
  end

  # TODO: Document this
  def fetch(payload) do
    <<type, payload::binary>> = payload
    type = decode_type(type)
    <<len, payload::binary>> = payload
    <<spec::binary-size(len), payload::binary>> = payload
    spec = decode_spec(type, spec)

    {%TorCell.Relay.Extend2.Spec{type: type, spec: spec}, payload}
  end

  # TODO: Document this
  def encode(spec) do
    encode_type(spec.type) <> encode_spec(spec.type, spec.spec)
  end
end
