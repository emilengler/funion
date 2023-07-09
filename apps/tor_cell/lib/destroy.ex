# SPDX-License-Identifier: ISC

defmodule TorCell.Destroy do
  @enforce_keys [:reason]
  defstruct reason: nil

  @type t :: %TorCell.Destroy{reason: reason()}
  @type reason ::
          :none
          | :protocol
          | :internal
          | :requested
          | :hibernating
          | :resourcelimit
          | :connectfailed
          | :or_identity
          | :channel_closed
          | :finished
          | :timeout
          | :destroyed

  @spec decode(binary()) :: TorCell.Destroy
  def decode(payload) do
    <<reason, _::binary-size(508)>> = payload

    reason =
      case reason do
        0 -> :none
        1 -> :protocol
        2 -> :internal
        3 -> :requested
        4 -> :hibernating
        5 -> :resourcelimit
        6 -> :connectfailed
        7 -> :or_identity
        8 -> :channel_closed
        9 -> :finished
        10 -> :timeout
        11 -> :destroyed
      end

    %TorCell.Destroy{reason: reason}
  end

  @spec encode(TorCell.Destroy) :: binary()
  def encode(cell) do
    reason =
      case cell.reason do
        :none -> <<0>>
        :protocol -> <<1>>
        :internal -> <<2>>
        :requested -> <<3>>
        :hibernating -> <<4>>
        :resourcelimit -> <<5>>
        :connectfailed -> <<6>>
        :or_identity -> <<7>>
        :channel_closed -> <<8>>
        :finished -> <<9>>
        :timeout -> <<10>>
        :destroyed -> <<11>>
      end

    reason <> <<0::508*8>>
  end
end
