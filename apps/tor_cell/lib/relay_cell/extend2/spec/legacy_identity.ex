defmodule TorCell.RelayCell.Extend2.Spec.LegacyIdentity do
  defstruct fingerprint: nil

  # TODO: Document this
  def decode(spec) do
    true = byte_size(spec) == 20
    %TorCell.RelayCell.Extend2.Spec.LegacyIdentity{fingerprint: spec}
  end

  # TODO: Document this
  def encode(spec) do
    true = byte_size(spec.fingerprint) == 20
    spec.fingerprint
  end
end
