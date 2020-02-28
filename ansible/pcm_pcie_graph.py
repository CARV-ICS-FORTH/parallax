"""
Generate a graph based on csv input
@author Michalis Vardoulakis
@email mvard@ics.forth.gr
"""
import matplotlib.pyplot as plt
import sys

def main():
  """ Main function """
  if len(sys.argv) != 3:
    print('Usage: ' + sys.argv[0] + ' <column> <input file>')

  infilename = sys.argv[2]
  column = int(sys.argv[1])
  infile = open(infilename, 'r')
  lines = infile.readlines()
  key = lines[0].split(',')[column - 1]
  values = [[], []]

  lines_to_skip = range(0, len(lines), 3)

  for i in range(0, len(lines)):
    if i in lines_to_skip:
      continue
    line = lines[i]
    column_values = line.split(',')
    values[int(column_values[0])].append(int(column_values[column - 1]))
  
  sums = [sum(x) for x in zip(*values)]

  plt.plot(range(1, len(sums) + 1), sums)
  plt.xlabel('Time (s)')
  plt.ylabel(key)
  plt.tight_layout()
  plt.savefig('fig.png', format='png')


if __name__ == '__main__':
  main()