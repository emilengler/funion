defmodule TorCell.Create2 do
  defstruct type: nil,
            data: nil

  @doc """
  Decodes the payload of a CREATE2 TorCell into its internal representation.

  Returns a TorCell.Create2 with type and data set accordingly.
  """
  def decode(payload) do
    <<0x02::16, payload::binary>> = payload
    <<len::16, payload::binary>> = payload
    <<data::binary-size(len), _>> = payload

    %TorCell.Create2{
      type: :ntor,
      data: data
    }
  end

  @doc """
  Encodes a TorCell.Create2 into a binary.

  Returns a binary corresponding to the payload of a CREATE2 TorCell.
  """
  def encode(cell) do
    :ntor = cell.type

    <<0x02::16>> <> <<byte_size(cell.data)::16>> <> cell.data
  end
end
