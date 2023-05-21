defmodule TorCellRelayExtend2Test do
  use ExUnit.Case
  doctest TorCell.Relay.Extend2
  doctest TorCell.Relay.Extend2.Spec
  doctest TorCell.Relay.Extend2.Spec.TlsOverTcp4
  doctest TorCell.Relay.Extend2.Spec.TlsOverTcp6
  doctest TorCell.Relay.Extend2.Spec.LegacyIdentity
  doctest TorCell.Relay.Extend2.Spec.Ed25519Identity

  test "decode a RELAY_EXTEND2 TorCell" do
    tls_over_tcp4 = <<0, 6>> <> <<1, 1, 1, 1, 0, 42>>
    tls_over_tcp6 = <<1, 18>> <> <<1::128, 0, 42>>
    legacy_identity = <<2, 20>> <> <<1::integer-size(20)-unit(8)>>
    ed25519_identity = <<3, 32>> <> <<42::integer-size(32)-unit(8)>>

    payload =
      <<4>> <>
        tls_over_tcp4 <>
        tls_over_tcp6 <> legacy_identity <> ed25519_identity <> <<0x02::16, 2::16, 42, 69>>

    assert TorCell.Relay.Extend2.decode(payload) == %TorCell.Relay.Extend2{
             specs: [
               %TorCell.Relay.Extend2.Spec{
                 type: :tls_over_tcp4,
                 spec: %TorCell.Relay.Extend2.Spec.TlsOverTcp4{ip: {1, 1, 1, 1}, port: 42}
               },
               %TorCell.Relay.Extend2.Spec{
                 type: :tls_over_tcp6,
                 spec: %TorCell.Relay.Extend2.Spec.TlsOverTcp6{
                   ip: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                   port: 42
                 }
               },
               %TorCell.Relay.Extend2.Spec{
                 type: :legacy_identity,
                 spec: %TorCell.Relay.Extend2.Spec.LegacyIdentity{
                   fingerprint: <<1::integer-size(20)-unit(8)>>
                 }
               },
               %TorCell.Relay.Extend2.Spec{
                 type: :ed25519_identity,
                 spec: %TorCell.Relay.Extend2.Spec.Ed25519Identity{
                   fingerprint: <<42::integer-size(32)-unit(8)>>
                 }
               }
             ],
             type: :ntor,
             data: <<42, 69>>
           }
  end
end
