defmodule TorCell.RelayCell.Extended2 do
  defstruct data: nil

  # TODO: Document this
  def decode(data) do
    <<len::16, data::binary>> = data
    <<data::binary-size(len)>> = data
    %TorCell.RelayCell.Extended2{data: data}
  end

  # TODO: Document this
  def encode(cell) do
    <<byte_size(cell.data)::16>> <> cell.data
  end
end
