# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extend2.Spec.Ed25519Identity do
  defstruct fingerprint: nil

  # TODO: Document this
  def decode(spec) do
    true = byte_size(spec) == 32
    %TorCell.RelayCell.Extend2.Spec.Ed25519Identity{fingerprint: spec}
  end

  # TODO: Document this
  def encode(spec) do
    true = byte_size(spec.fingerprint) == 32
    spec.fingerprint
  end
end
