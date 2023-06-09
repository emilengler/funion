# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extend2.Spec.Ed25519Identity do
  @enforce_keys [:fingerprint]
  defstruct fingerprint: nil

  @type t :: %TorCell.RelayCell.Extend2.Spec.Ed25519Identity{fingerprint: :crypto.ecdh_public()}

  @spec decode(binary()) :: t()
  def decode(spec) do
    remaining = spec
    <<pubkey::binary-size(32), _::binary>> = remaining

    %TorCell.RelayCell.Extend2.Spec.Ed25519Identity{fingerprint: pubkey}
  end

  @spec encode(t()) :: binary()
  def encode(spec) do
    spec.fingerprint
  end
end
