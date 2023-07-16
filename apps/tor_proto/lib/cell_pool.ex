# SPDX-License-Identifier: ISC

defmodule TorProto.CellPool do
  @moduledoc """
  Implements a cell pool, which is a pool in which each PID
  has their own space to store cells.
  Each cell may only be obtained once, meaning that read cells
  are removed from the cell pool thereafter.
  Each cell is identified by a unique integer, that is unique
  among all PID's and is never going to be re-assigned.
  """
  @enforce_keys [:cells, :n]
  defstruct cells: nil,
            n: 0

  @type t :: %TorProto.CellPool{cells: %{pid() => %{integer() => TorCell.t()}}}

  @doc """
  Initializes the cell pool.
  """
  @spec init() :: t()
  def init() do
    %TorProto.CellPool{cells: %{}, n: 0}
  end

  @doc """
  Pushes a new cell to the end of a PID's cell pool,
  assigning it a unique id, that is returned in the tuple.
  """
  @spec push(t(), pid(), TorCell.t()) :: {t(), integer()}
  def push(pool, pid, cell) do
    # The cell pool
    cells = pool.cells
    # The unique integer
    n = pool.n

    # Fetch the integer() => TorCell.t() association
    pids_pool = Map.get(cells, pid, %{})
    pids_pool = Map.put(pids_pool, n, cell)
    cells = Map.put(cells, pid, pids_pool)

    {%TorProto.CellPool{cells: cells, n: n + 1}, n}
  end

  @doc """
  Returns and removes the last item in a PID's cell pool.
  """
  @spec pop(t(), pid()) :: {t(), TorCell.t() | nil}
  def pop(pool, pid) do
    cells = pool.cells
    pids_pool = Map.get(cells, pid)

    if pids_pool == nil do
      {pool, nil}
    else
      last_id = List.last(Map.keys(pids_pool))
      take(pool, pid, last_id)
    end
  end

  @doc """
  Returns and removes a cell identified its unique id from a PID's
  cell pool.
  """
  @spec take(t(), pid(), integer()) :: {t(), TorCell.t() | nil}
  def take(pool, pid, id) do
    cells = pool.cells
    pids_pool = Map.get(cells, pid)

    if pids_pool == nil do
      {pool, nil}
    else
      {cell, pids_pool} = Map.pop(pids_pool, id, nil)

      cells =
        if length(Map.keys(pids_pool)) == 0 do
          # Remove empty PIDs
          Map.delete(cells, pid)
        else
          Map.put(cells, pid, pids_pool)
        end

      {%TorProto.CellPool{cells: cells, n: pool.n}, cell}
    end
  end
end
