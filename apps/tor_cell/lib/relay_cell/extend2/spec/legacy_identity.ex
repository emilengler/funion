# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extend2.Spec.LegacyIdentity do
  @enforce_keys [:fingerprint]
  defstruct fingerprint: nil

  @type t :: %TorCell.RelayCell.Extend2.Spec.LegacyIdentity{fingerprint: binary()}

  @spec decode(binary()) :: TorCell.RelayCell.Extend2.Spec.LegacyIdentity
  def decode(spec) do
    remaining = spec
    <<pubkey::binary-size(20), _::binary>> = remaining

    %TorCell.RelayCell.Extend2.Spec.LegacyIdentity{fingerprint: pubkey}
  end

  @spec encode(TorCell.RelayCell.Extend2.Spec.LegacyIdentity) :: binary()
  def encode(spec) do
    spec.fingerprint
  end
end
