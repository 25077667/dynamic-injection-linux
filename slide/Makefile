src = main.tex
target = main.pdf
middles = $(shell pwd)/build
TEX = xelatex

.PHONY: mkdir all clean

$(middles)/$(target): $(src) mkdir
	$(TEX) -no-shell-escape -output-directory="$(middles)" $<
	$(TEX) -no-shell-escape -output-directory="$(middles)" $<

all: $(middles)/$(target)

mkdir:
	mkdir -p $(middles)

clean:
	$(RM) -r $(middles)
