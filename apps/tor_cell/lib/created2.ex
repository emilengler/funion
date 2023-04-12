defmodule TorCell.Created2 do
  defstruct data: nil

  @doc """
  Decodes the payload of a CREATED2 TorCell into its internal representation.

  Returns a TorCell.Created2 with type and data set accordingly.
  """
  def decode(payload) do
    <<len::16, payload::binary>> = payload
    <<data::binary-size(len), _::binary>> = payload

    %TorCell.Created2{
      data: data
    }
  end

  @doc """
  Encodes a TorCell.Created2 into a binary.

  Returns a binary corresponding to the payload of a CREATED2 TorCell.
  """
  def encode(cell) do
    <<byte_size(cell.data)::16>> <> cell.data
  end
end
