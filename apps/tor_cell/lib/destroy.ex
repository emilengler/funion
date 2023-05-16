defmodule TorCell.Destroy do
  defstruct reason: nil

  @doc """
  Decodes the payload of a DESTROY TorCell into its internal representation.

  Returns a TorCell.Destroy with reason set to the error code as an atom.
  """
  def decode(payload) do
    <<error, _::binary-size(508)>> = payload

    %TorCell.Destroy{
      reason:
        case error do
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
    }
  end

  @doc """
  Encodes a TorCell.Destroy into a binary.

  Returns a binary corresponding to the payload of a DESTROY TorCell.
  """
  def encode(cell) do
    error =
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

    error <> <<0::508*8>>
  end
end
