# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.End do
  @enforce_keys [:reason]
  defstruct reason: nil

  @type t :: %TorCell.RelayCell.End{reason: reason()}
  @type reason ::
          :misc
          | :resolvefailed
          | :connectrefused
          | :destroy
          | :done
          | :timeout
          | :noroute
          | :hibernating
          | :internal
          | :resourcelimit
          | :connreset
          | :torprotocol
          | :notdirectory

  @spec decode_reason(integer()) :: reason()
  defp decode_reason(reason) do
    case reason do
      1 -> :misc
      2 -> :resolvefailed
      3 -> :connectrefused
      # TODO: Add exitpolicy
      5 -> :destroy
      6 -> :done
      7 -> :timeout
      8 -> :noroute
      9 -> :hibernating
      10 -> :internal
      11 -> :resourcelimit
      12 -> :connreset
      13 -> :torprotocol
      14 -> :notdirectory
    end
  end

  @spec encode_reason(reason()) :: binary()
  defp encode_reason(reason) do
    case reason do
      :misc -> <<1>>
      :resolvefailed -> <<2>>
      :connectrefused -> <<3>>
      # TODO: Add exitpolicy
      :destroy -> <<5>>
      :done -> <<6>>
      :timeout -> <<7>>
      :noroute -> <<8>>
      :hibernating -> <<9>>
      :internal -> <<10>>
      :resourcelimit -> <<11>>
      :connreset -> <<12>>
      :torprotocol -> <<13>>
      :notdirectory -> <<14>>
    end
  end

  @spec decode(binary()) :: t()
  def decode(data) do
    <<reason, _::binary>> = data
    reason = decode_reason(reason)

    # TODO: Handle exitpolicy edge case
    %TorCell.RelayCell.End{reason: reason}
  end

  @spec encode(t()) :: binary()
  def encode(cell) do
    encode_reason(cell.reason)
  end
end
