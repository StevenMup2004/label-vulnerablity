require "json"
require "linguist"

LANGUAGES = [
  "C",
  "C++",
  "Java",
  "JavaScript",
  "TypeScript",
  "Python",
  "PHP",
  "Ruby",
  "C#",
  "Go",
  "Rust",
  "Scala",
  "Objective-C",
  "Objective-C++",
  "Swift",
  "Kotlin",
  "Lua",
  "Perl"
].freeze

DB = Linguist::Samples.cache

STDIN.each_line do |line|
  obj = nil

  begin
    obj = JSON.parse(line)

    id = obj["id"]
    code = obj["code"].to_s

    if code.strip.length < 10
      puts JSON.generate({
        id: id,
        language: nil,
        score: 0.0,
        top3: []
      })

      STDOUT.flush
      next
    end

    scores = Linguist::Classifier.classify(
      DB,
      code,
      LANGUAGES
    )

    top = scores.first

    puts JSON.generate({
      id: id,
      language: top ? top[0] : nil,
      score: top ? top[1] : 0.0,
      top3: scores.first(3)
    })

    STDOUT.flush

  rescue => e

    puts JSON.generate({
      id: obj ? obj["id"] : nil,
      language: nil,
      score: 0.0,
      top3: [],
      error: "#{e.class}: #{e.message}"
    })

    STDOUT.flush
  end
end