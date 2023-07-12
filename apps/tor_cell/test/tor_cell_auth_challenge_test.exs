# SPDX-License-Identifier: ISC

defmodule TorCellAuthChallengeTest do
  use ExUnit.Case
  doctest TorCell.AuthChallenge

  test "decodes an TorCell.AuthChallenge cell" do
    payload = <<42::32*8>> <> <<2::16>> <> <<1::16, 3::16>>

    assert TorCell.AuthChallenge.decode(payload) == %TorCell.AuthChallenge{
             challenge: <<42::32*8>>,
             methods: [:rsa_sha256_tlssecret, :ed25519_sha256_rfc5705]
           }
  end

  test "decodes an empty TorCell.AuthChallenge cell" do
    assert TorCell.AuthChallenge.decode(<<42::32*8, 0::16>>) == %TorCell.AuthChallenge{
             challenge: <<42::32*8>>,
             methods: []
           }
  end

  test "encodes an TorCell.AuthChallenge cell" do
    cell = %TorCell.AuthChallenge{
      challenge: <<42::32*8>>,
      methods: [:rsa_sha256_tlssecret, :ed25519_sha256_rfc5705]
    }

    assert TorCell.AuthChallenge.encode(cell) == <<42::32*8>> <> <<2::16>> <> <<1::16, 3::16>>
  end
end
